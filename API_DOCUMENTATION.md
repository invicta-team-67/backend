# TrustBridge Backend API Documentation
Secure  API for business transaction verification with proof upload capabilities. Built with Express.js, Supabase, and JWT authentication

All protected endpoints require a Bearer token in the Authorization header:
## Base URL
- Local: `http://localhost:3000`
- Production: `https://backend-jtvn.onrender.com`

## Authentication
- Protected endpoints require a Supabase access token in the `Authorization` header:
  - `Authorization: Bearer <supabase_access_token>`
- Public endpoint:
  - `GET /confirm`

## Environment Variables
- `SUPABASE_URL`
- `SUPABASE_SERVICE_ROLE_KEY`
- `JWT_SECRET`
- `CONFIRM_BASE_URL` (must start with `https://trustbridgee.netlify.app`)

## Endpoints

### 1. Get Report Data
Retrieves business profile and verified transaction statistics for the authenticated user.
- Method: `GET`
- Path: `/report-data`
- Auth: Required

Response `200`:
```json
{
  "business": {
    "id": "uuid",
    "business_name": "Acme Ltd"
  },
  "stats": {
    "verifiedTransactions": 3,
    "totalTransactionVolume": 12500,
    "trustScore": 30
  },
  "transactions": [
    {
      "amount": "2500",
      "created_at": "2026-02-25T12:00:00.000Z",
      "status": "verified"
    }
  ]
}
```

Common errors:
- `401` Unauthorized / token missing
- `500` Server or database error

Trust score logic:
- `trustScore = min(number_of_verified_transactions * 10, 100)`

### 2. Upload Proof File
- Method: `POST`
- Path: `/upload-proof`
- Auth: Required
- Content-Type: `multipart/form-data`
- Form fields:
  - `transactionId` (string, required)
  - `file` (required)

File validation:
- Max size: `5MB`
- Allowed MIME types:
  - `application/pdf`
  - `image/jpeg`
  - `image/png`

Success `200`:
```json
{
  "message": "Proof uploaded successfully"
}
```

Common errors:
- `400` Missing `transactionId` or file
- `400` Invalid MIME type
- `400` File too large
- `403` Forbidden (transaction not owned by authenticated user)
- `404` Transaction not found
- `500` Upload/server error

### 3. Generate Confirmation Link
- Method: `POST`
- Path: `/generate-confirmation`
- Auth: Required
- Content-Type: `application/json`

Request body:
```json
{
  "transactionId": "txn_123"
}
```

Success `200`:
```json
{
  "confirmationLink": "https://trustbridgee.netlify.app/confirm?token=<jwt>"
}
```

Security behavior:
- Only transaction owner can generate token (`403` otherwise)
- Token is signed with `HS256`
- Token expires in `72h`
- DB stores SHA-256 hash of token, not raw token

Common errors:
- `400` Missing `transactionId`
- `403` Forbidden
- `404` Transaction not found
- `500` Failed to store token/server error

### 4. Confirm Transaction
Public endpoint to verify a transaction using a confirmation token. Typically accessed via email link.
- Method: `GET`
- Path: `/confirm`
- Auth: Not required
- Query params:
  - `token` (required)

Example:
- `/confirm?token=<jwt>`

Success `200` (text):
- `Transaction Verified Successfully`

Validation checks:
- Token must be present
- JWT must be valid and signed with `HS256`
- Token hash must match `confirmation_token_hash` in DB
- Token must not be used already
- Token must not be expired

Common errors (text):
- `400` `Token required`
- `400` `Invalid token`
- `400` `Token already used`
- `400` `Token expired`
- `400` `Invalid or Expired Token`

## cURL Examples

### Get report data
```bash
curl -X GET "https://backend-jtvn.onrender.com/report-data" \
  -H "Authorization: Bearer <supabase_access_token>"
```

### Upload proof
Uploads verification documentation for a specific transaction
```bash
curl -X POST "https://backend-jtvn.onrender.com/upload-proof" \
  -H "Authorization: Bearer <supabase_access_token>" \
  -F "transactionId=txn_123" \
  -F "file=@/path/to/proof.pdf"
```

### Generate confirmation link
Creates a secure, time-limited confirmation token for transaction verification
```bash
curl -X POST "https://backend-jtvn.onrender.com/generate-confirmation" \
  -H "Authorization: Bearer <supabase_access_token>" \
  -H "Content-Type: application/json" \
  -d '{"transactionId":"txn_123"}'
```
### dependencies
express - Web framework
@supabase/supabase-js - Database client
jsonwebtoken - JWT signing/verification
multer - File upload handling
crypto - Random bytes and hashing (Node.js native)
dotenv - Environment variable management