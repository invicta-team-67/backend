
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
if (
  !process.env.SUPABASE_URL ||
  !process.env.SUPABASE_SERVICE_ROLE_KEY ||
  !process.env.JWT_SECRET ||
  !process.env.CONFIRM_BASE_URL
) {
  // Fail fast at boot if any critical secret/config is missing.
  console.error("Missing required environment variables");//logs error of any required env variable are missing
  process.exit(1); //exits process with faillure code
}

// Force HTTPS for confirmation links so tokens are never sent over plain HTTP.
if (!process.env.CONFIRM_BASE_URL.startsWith("https://")) {
  console.error("CONFIRM_BASE_URL must start with https://");
  process.exit(1);
}
// creating supabase client with URL and service key
const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);


// 3. FILE UPLOAD CONFIG


// configuring multer to store uploaded file in memory 
// Explicit file-type allowlist to block unexpected or malicious uploads.
const ALLOWED_MIME_TYPES = ["application/pdf", "image/jpeg", "image/png"];
const upload = multer({
  storage: multer.memoryStorage(),
  // Cap file size at 5MB to reduce abuse and memory pressure.
  limits: { fileSize: 5 * 1024 * 1024 },
  fileFilter(req, file, cb) {
    // Reject any MIME type outside our allowlist.
    if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
      return cb(new Error("Invalid file type. Only PDF, JPEG, and PNG are allowed."));
    }
    // Accept file when MIME type is allowed.
    cb(null, true);
  },
});


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
      .eq("id", userId)
      .single();

    if (profileError) //if profile query fails,return 500 with DB error message
      return res.status(500).json({ error: profileError.message });

    // Fetch verified transactions
    const { data: transactions, error: txError } = await supabase //queries transactions filtered by user_id and verified status
      .from("transactions")
      .select("amount, created_at, status")
      .eq("user_id", userId)
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

      // Lookup transaction owner to enforce tenant isolation.
      const { data: transaction, error: txLookupError } = await supabase
        .from("transactions")
        .select("transaction_id, user_id")
        .eq("transaction_id", transactionId)
        .single();

      if (txLookupError || !transaction) {
        return res.status(404).json({ error: "Transaction not found" });
      }

      // Only the authenticated owner of this transaction can upload proof for it.
      if (transaction.user_id !== req.user.id) {
        return res.status(403).json({ error: "Forbidden" });
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

    // Read owner (user_id) so we can authorize confirmation-token generation.
    const { data: transaction, error: txLookupError } = await supabase
      .from("transactions")
      .select("transaction_id, user_id")
      .eq("transaction_id", transactionId)
      .single();

    if (txLookupError || !transaction) {
      return res.status(404).json({ error: "Transaction not found" });
    }

    // Critical ownership check: prevent one user generating tokens for another user's transaction.
    if (transaction.user_id !== req.user.id) {
      return res.status(403).json({ error: "Forbidden" });
    }

    const nonce = crypto.randomBytes(32).toString("hex"); //generates random 32 byte nonce as hex string

    const token = jwt.sign( //signs jwt containing transaction id and nonce and expires in 72hrs using JWT-SECRET
      { transaction_id: transactionId, nonce },
      process.env.JWT_SECRET,
      {
        expiresIn: "72h",
        // Pin signing algorithm explicitly to avoid algorithm confusion or downgrade behavior.
        algorithm: "HS256",
      }
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

    // Build external confirmation URL from env so production uses HTTPS domain, not localhost HTTP.
    const link = `${process.env.CONFIRM_BASE_URL}/confirm?token=${encodeURIComponent(token)}`; //building confirmation url with token query param

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

    // During verification, only accept HS256-signed tokens.
    const decoded = jwt.verify(token, process.env.JWT_SECRET, {
      algorithms: ["HS256"],
    }); //verifies JWT signature + expiry with JWT SECRET decodes payload

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


app.use((err, req, res, next) => {
  // Handle multer-specific upload errors with user-friendly 400 responses.
  if (err instanceof multer.MulterError) {
    if (err.code === "LIMIT_FILE_SIZE") {
      return res.status(400).json({ error: "File too large. Max size is 5MB." });
    }
    return res.status(400).json({ error: err.message });
  }

  // Handle non-multer upload validation errors like invalid MIME type
  if (err) {
    return res.status(400).json({ error: err.message || "Invalid file upload" });
  }

  next();
});

const PORT = process.env.PORT || 3000; //use Render-assigned port in production, fallback locally
app.listen(PORT, () => { //starts express server
  console.log(`Server running on port ${PORT}`);
});
