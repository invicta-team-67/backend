// Creating the server
require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.json());

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_ROLE_KEY
);
// starts server at 3000
app.listen(3000, () => {
  console.log("Server running on port 3000");
});


// TOKEN GENERATION ENDPOINT
app.post('/generate-confirmation', async (req, res) => {
  const { transactionId } = req.body;

  const nonce = crypto.randomBytes(32).toString('hex'); //generate random 64 char secure string
//    creates JWT
  const token = jwt.sign(
    {
      transaction_id: transactionId,
      nonce: nonce
    },
    process.env.JWT_SECRET,
    { expiresIn: '72h' }
  );
// Hashing the token for database storage(security control:single use enforcement)
  const tokenHash = crypto
    .createHash('sha256')
    .update(token)
    .digest('hex');

  const expiresAt = new Date(Date.now() + 72 * 60 * 60 * 1000);
// store Hash in Supabase transaction table
  await supabase
    .from('transactions')
    .update({
      confirmation_token_hash: tokenHash,
      confirmation_expires_at: expiresAt,
      confirmation_used: false
    })
    .eq('id', transactionId);

  const link = `http://localhost:3000/confirm?token=${token}`;

  res.json({ confirmationLink: link });
});

// CONFIRMATION ENDPOINT
app.get('/confirm', async (req, res) => {
  const { token } = req.query;

  try {
    // verify signature and Expiration
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    //  Hash incoming token to compare with
    const incomingHash = crypto
      .createHash('sha256')
      .update(token)
      .digest('hex');
    // Check DB for matching Hash(ensure token wasnt already used)
    const { data: transaction } = await supabase
      .from('transactions')
      .select('*')
      .eq('id', decoded.transaction_id)
      .eq('confirmation_token_hash', incomingHash)
      .single();

    if (!transaction)
      return res.status(400).send("Invalid token");

    if (transaction.confirmation_used)
      return res.status(400).send("Token already used");

    if (new Date() > new Date(transaction.confirmation_expires_at))
      return res.status(400).send("Token expired");
    // Atomic Update:verify transaction and Null the hash
    await supabase
      .from('transactions')
      .update({
        status: 'verified',
        confirmation_used: true //invalidate token immediately
      })
      .eq('id', decoded.transaction_id);

    res.send("Transaction Verified Successfully");

  } catch (err) {
    res.status(400).send("Invalid or Expired Token");
  }
});
