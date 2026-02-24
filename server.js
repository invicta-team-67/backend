
// 1. INITIAL SETUP

require("dotenv").config(); //load env variables into process.env
const express = require("express"); //importing express framework
const jwt = require("jsonwebtoken"); //import JWT for signing and verifying tokens
const crypto = require("crypto"); //importing node module for random bytes and hashing
const multer = require("multer"); //import for handling file upload
const { createClient } = require("@supabase/supabase-js"); //function that connects code to supabase database

const app = express(); //creating express app instance
app.use(express.json()); //automatically parse json data sent in request body


// 2. SUPABASE CLIENT

//checking if required environment variables are missing
// if (
//   !process.env.SUPABASE_URL ||
//   !process.env.SUPABASE_SERVICE_ROLE_KEY ||
//   !process.env.JWT_SECRET
// ) {
//   console.error("Missing required environment variables");//logs error of any required env variable are missing
//   process.exit(1); //exits process with faillure code
// }
// creating supabase client with URL and service key
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);


// 3. FILE UPLOAD CONFIG


// configuring multer to store uploaded file in memory 
const upload = multer({ storage: multer.memoryStorage() });


// 4. AUTH MIDDLEWARE


async function authenticate(req, res, next) { //declaring async middleware
  try { //starting try for safe authentication
    const token = req.headers.authorization?.split(" ")[1]; //reading bearer token from authorization header

    if (!token) { //if the token is missing return 401 error in json
      return res.status(401).json({ error: "Authorization token required" });
    }

    // calling supbase.auth.getuser to validate token and get user

    const {
      data: { user },
      error,
    } = await supabase.auth.getUser(token);

    // if supabase returns error or no user ,return 401 unauthorized

    if (error || !user) {
      return res.status(401).json({ error: "Unauthorized" });
    }

    // attaches authenticated user to req.user

    req.user = user;
    next(); //calls this to ontinue route chain
  } catch (err) {
    return res.status(500).json({ error: "Authentication failed" }); //on unexpected auth faillure,return 500 authentication failed
  }
}


// 5. REPORT DATA ENDPOINT


app.get("/report-data", authenticate, async (req, res) => { //defining GET protected by authenticate
  try { //start try block
    const userId = req.user.id; //get current authenticated user id

    // Fetch profile
    const { data: business, error: profileError } = await supabase //queries profile table and expects one row
      .from("profiles")
      .select("*")
      .eq("user_id", userId)
      .single();

    if (profileError) //if profile query fails,return 500 with DB error message
      return res.status(500).json({ error: profileError.message });

    // Fetch verified transactions
    const { data: transactions, error: txError } = await supabase //queries transaction with selected columns filtered by sme-d and status verified
      .from("transactions")
      .select("amount, created_at, status")
      .eq("sme_id", userId)
      .eq("status", "verified");

    if (txError) //if transaction fails, return 500
      return res.status(500).json({ error: txError.message });

    const verifiedCount = transactions.length; //count verified transactions
    const totalVolume = transactions.reduce(
      (sum, tx) => sum + Number(tx.amount),
      0
    );

    const trustScore = Math.min(verifiedCount * 10, 100);

    res.json({ //return json  containing profile
      business,
      stats: {
        verifiedTransactions: verifiedCount,
        totalTransactionVolume: totalVolume,
        trustScore,
      },
      transactions,
    });
  } catch (err) { //catches all server error
    res.status(500).json({ error: "Server error" });
  }
});


// 6. FILE UPLOAD ENDPOINT


app.post(
  "/upload-proof",
  authenticate,
  upload.single("file"),
  async (req, res) => {
    try {
      const { transactionId } = req.body; //reading transaction ID from request body
      const file = req.file; //reads uploaded file from req.file

      if (!transactionId || !file) { //validate both transactionid and file and returns 400 if missing
        return res
          .status(400)
          .json({ error: "transactionId and file are required" });
      }

      const filePath = `${transactionId}/${Date.now()}-${ //building storage path
        file.originalname
      }`;

      const { error } = await supabase.storage //uploads file buffer into supabase storage bucket with MIME type
        .from("proof-files")
        .upload(filePath, file.buffer, {
          contentType: file.mimetype,
        });

      if (error)
        return res.status(500).json({ error: "Upload failed" });

      await supabase
        .from("transactions")
        .update({ proof_files_urls: filePath })
        .eq("transaction_id", transactionId);

      res.json({ message: "Proof uploaded successfully" });
    } catch (err) {
      res.status(500).json({ error: "Server error" });
    }
  }
);


// 7. GENERATE CONFIRMATION TOKEN


app.post("/generate-confirmation", authenticate, async (req, res) => {
  try {
    const { transactionId } = req.body; //reads transactionid from request body

    if (!transactionId) //if missing returns 400
      return res.status(400).json({ error: "transactionId required" });

    const { data: transaction, error: txLookupError } = await supabase
      .from("transactions")
      .select("transaction_id, sme_id")
      .eq("transaction_id", transactionId)
      .single();

    if (txLookupError || !transaction) {
      return res.status(404).json({ error: "Transaction not found" });
    }

   

    const nonce = crypto.randomBytes(32).toString("hex"); //generates random 32 byte nonce as hex string

    const token = jwt.sign( //signs jwt containing transaction id and nonce and expires in 72hrs using JWT-SECRET
      { transaction_id: transactionId, nonce },
      process.env.JWT_SECRET,
      { expiresIn: "72h" }
    );

    const tokenHash = crypto //Hashes the JWT using SHA-256(stores hash,not raw token)
      .createHash("sha256")
      .update(token)
      .digest("hex");

    const expiresAt = new Date(Date.now() + 72 * 60 * 60 * 1000); //computes expiration timestamp

    const { error: updateError, data: updatedRows } = await supabase //updates transaction row  with token hash,expire and confirmation used
      .from("transactions")
      .update({
        confirmation_token_hash: tokenHash,
        confirmation_expires_at: expiresAt,
        confirmation_used: false,
      })
      .eq("transaction_id", transactionId)
      .select("transaction_id");

    if (updateError) {
      return res
        .status(500)
        .json({ error: `Failed to store confirmation token: ${updateError.message}` });
    }

    if (!updatedRows || updatedRows.length === 0) {
      return res
        .status(404)
        .json({ error: "Transaction not found for this user" });
    }

    const link = `http://localhost:3000/confirm?token=${encodeURIComponent(token)}`; //building confirmation url with token query param

    res.json({ confirmationLink: link }); //returns confirmation link  json
  } catch (err) { //catch returns generic 500
    res.status(500).json({ error: "Server error" });
  }
});


// 8. CONFIRM TRANSACTION


app.get("/confirm", async (req, res) => { //define public route
  try { //start try
    const rawToken = req.query.token; //reads token from query string
    const token = typeof rawToken === "string" ? decodeURIComponent(rawToken) : null;

    if (!token) //if token missing return 400 text response
      return res.status(400).send("Token required");

    const decoded = jwt.verify(token, process.env.JWT_SECRET); //verifies JWT signature + expiry with JWT SECRET decodes payload

    const incomingHash = crypto //hashes incoming token for DB comparison
      .createHash("sha256")
      .update(token)
      .digest("hex");

    const { data: transaction, error: txError } = await supabase //fetches transaction where id matches  decoded transactionid and stored hash matches incoming hash
      .from("transactions")
      .select("*")
      .eq("transaction_id", decoded.transaction_id)
      .eq("confirmation_token_hash", incomingHash)
      .single();

    if (txError) {
      return res.status(400).send("Invalid token");
    }

    if (!transaction) //if no row found token invalid
      return res.status(400).send("Invalid token");

    if (transaction.confirmation_used) //if already used reject
      return res.status(400).send("Token already used");

    if (new Date() > new Date(transaction.confirmation_expires_at)) //if current time past stored expiry reject
      return res.status(400).send("Token expired");

    await supabase
      .from("transactions")
      .update({
        status: "verified",
        confirmation_used: true,
      })
      .eq("transaction_id", decoded.transaction_id);

    res.send("Transaction Verified Successfully"); //send success response
  } catch (err) { //any verify DB exception retuns 400 invalid or expired token 
    res.status(400).send("Invalid or Expired Token");
  }
});


// 9. START SERVER


const PORT = 3000; //sends to port 3000
app.listen(PORT, () => { //starts express server
  console.log(`Server running on port ${PORT}`);
});
