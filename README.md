# Secure Password Vault Backup API

**Target Platform & Framework:** .NET 10 / C# 14 Minimal APIs & Class Libraries + Web Protocol Summary

---

## 1. Solution Architecture

This repository implements a zero-knowledge, end-to-end encrypted backup and retrieval service for a password manager. The server never receives or stores plaintext passwords, plaintext vaults, or private encryption keys. All cryptographic operations (key derivation, signing, and encryption/decryption) take place entirely client-side.

```
VaultBackup/
├── VaultBackup.sln
├── README.md                     # Comprehensive architecture, decisions, threat model, & runbook
├── VaultShared/                  # Shared Class Library (.NET 10)
│   ├── VaultShared.csproj
│   ├── Crypto/
│   │   ├── KeyDerivation.cs      # PBKDF2-HMAC-SHA256 + HKDF-SHA256 key derivation
│   │   ├── SigningService.cs     # ECDSA P-256 signing, verification, and canonical message assembly
│   │   └── VaultCipher.cs        # Authenticated AES-256-GCM client-side vault encryption
│   └── Protocol/
│       ├── Envelope.cs           # RequestEnvelope { email, payload, nonce, signature } & ApiErrorResponse
│       ├── Payloads.cs           # DTOs: RegisterRequest, VerifyPayload, StorePayload, RetrievePayload
│       └── PayloadCodec.cs       # Base64/JSON codecs & signed envelope builder
├── VaultServer/                  # ASP.NET Core Web API (.NET 10)
│   ├── VaultServer.csproj
│   ├── Program.cs                # Route endpoints, DI composition, and error mappings
│   ├── appsettings.json          # SQLite connection string and logging configuration
│   ├── Data/
│   │   ├── schema.sql            # Idempotent SQLite table DDL
│   │   └── VaultDbContext.cs     # SQLite connection pool & initialization
│   └── Services/
│       ├── AccountService.cs     # Registration, mock verification, account lookups
│       ├── VaultStoreService.cs  # Atomic blob storage & retrieval
│       └── AuthMiddleware.cs     # Envelope parsing, replay rejection, ECDSA signature verification
├── VaultClient/                  # Console Application (.NET 10)
│   ├── VaultClient.csproj
│   └── Program.cs                # 7-step full workflow + 4 negative attack test cases
└── server.ts / src/              # Minimal Node/Vite host for preview
```

---

## 2. Locked-In Design Decisions

| Area | Decision | Rationale |
|---|---|---|
| **Signature Scheme** | **ECDSA over NIST P-256 (`secp256r1`)** with SHA-256 | Native support across standard runtimes (`System.Security.Cryptography.ECDsa`, WebCrypto, OpenSSL). High performance, compact 64-byte signatures, and 128-bit security level without third-party dependencies. |
| **Public Key Format** | **PEM (SubjectPublicKeyInfo / SPKI X.509)** | Standard self-describing format embedding curve OID, interoperable with `openssl` and standard key infrastructure. |
| **Password Stretching** | **PBKDF2-HMAC-SHA256**, 600,000 iterations, salt = `UTF8(email.ToLowerInvariant())` | Matches OWASP 2023 password storage recommendations; available natively in .NET BCL (`Rfc2898DeriveBytes.Pbkdf2`) and WebCrypto without native C binaries. |
| **Domain Separation** | Master Secret $\to$ **HKDF-SHA256** with unique info labels | Creates distinct cryptographic contexts: `"vault-backup:signing-key:v1"` for authentication and `"vault-backup:encryption-key:v1"` for AES-256 data protection. Compromise or analysis of one derived key does not weaken the other. |
| **Vault Encryption** | **AES-256-GCM** (12-byte random IV, 16-byte GMAC authentication tag) | Authenticated Encryption with Associated Data (AEAD) ensures both confidentiality and tamper detection. Format: `Base64(Nonce[12] \|\| Tag[16] \|\| Ciphertext[N])`. Server stores opaque base64 blob only. |
| **Signed Message Construction** | `UTF8(email) \|\| 0x00 \|\| rawPayloadBytes \|\| 0x00 \|\| UTF8(nonce)` | Null-byte (`0x00`) separators prevent canonicalization ambiguity and field splicing attacks. Operating directly over raw payload bytes avoids JSON serialization formatting and whitespace divergence issues. |
| **Replay Protection** | **Monotonically Increasing Nonce** (Unix millisecond timestamp) | Server persists `LastNonce` per account. Rejects any request where `nonce <= account.LastNonce` with `409 Conflict (replayed_nonce)`. Nonce is only committed to storage upon entire request success. |
| **Registration & Verification** | Unsigned `POST /register` $\to$ unverified account $\to$ mocked verification token $\to$ signed `POST /verify` | Satisfies the requirement: initial registration is unsigned; store and retrieve require prior verification. Mocked token allows automated testability. |
| **Server Storage** | **SQLite** (`vault.db`) with Write-Ahead Logging (`PRAGMA journal_mode=WAL`) | Zero-configuration, file-backed durable persistence across process restarts. |
| **Error Handling** | Standardized `{ "error": "<code>", "message": "<description>" }` | Machine-parseable error codes with descriptive messages matching standard HTTP status codes (400, 403, 404, 409, 410). |

---

## 3. Wire Protocol & Endpoints

All authenticated requests wrap the inner command in a JSON envelope:

```json
{
  "email": "user@example.com",
  "payload": "<Base64 encoded UTF-8 JSON payload>",
  "nonce": 1737000000000,
  "signature": "<Base64 encoded ECDSA signature over canonical byte string>"
}
```

### Canonical Signed Message Format

```
canonicalMessage = UTF8(email.ToLowerInvariant()) + 0x00 + rawPayloadBytes + 0x00 + UTF8(nonce.ToString())
```

### Endpoint Matrix

| Method & Route | Auth Required | Request Body | Success Response | Error Codes |
|---|---|---|---|---|
| `POST /register` | None (Unsigned) | `{ "email": "...", "publicKeyPem": "..." }` | `201 Created` `{ "email": "...", "verificationToken": "..." }` | `400 malformed_request`<br>`409 email_already_registered` |
| `POST /verify` | Signed Envelope (`type: "verify"`) | Envelope with payload `{ "type": "verify", "token": "..." }` | `200 OK` `{ "verified": true }` | `400 invalid_signature`<br>`404 account_not_found`<br>`409 replayed_nonce`<br>`410 token_already_used` |
| `POST /store` | Signed Envelope (`type: "store"`) | Envelope with payload `{ "type": "store", "vault": "<base64>" }` | `200 OK` `{ "storedAt": "...", "status": "stored" }` | `400 invalid_signature`<br>`403 account_unverified`<br>`409 replayed_nonce` |
| `POST /retrieve` | Signed Envelope (`type: "retrieve"`) | Envelope with payload `{ "type": "retrieve" }` | `200 OK` `{ "vault": "<base64>", "updatedAt": "..." }` | `400 invalid_signature`<br>`403 account_unverified`<br>`404 vault_not_found`<br>`409 replayed_nonce` |

### Server-Side Validation Pipeline (Verify / Store / Retrieve)

1. **Envelope Parse**: Extract `email`, `payload` (Base64), `nonce`, and `signature` (Base64).
2. **Account Lookup**: Query account by email. If not found $\to$ `404 account_not_found`.
3. **Verification Check**: If endpoint requires verified account (e.g. `/store`, `/retrieve`) and `Verified == 0` $\to$ `403 account_unverified`.
4. **Replay Nonce Check**: Validate `nonce > account.LastNonce`. If not $\to$ `409 replayed_nonce`.
5. **Canonical Message Assembly**: Reconstruct `UTF8(email) || 0x00 || rawPayloadBytes || 0x00 || UTF8(nonce)`.
6. **Signature Verification**: Verify ECDSA P-256 signature against stored `PublicKeyPem`. If invalid $\to$ `400 invalid_signature`.
7. **Payload Processing & Atomic Commit**: Execute handler and commit `LastNonce = nonce` within the same database transaction.

---

## 4. Threat Model & Security Analysis

### 1. Zero-Knowledge Server & Confidentiality
- **Threat**: Attacker breaches server database, filesystem, or memory.
- **Protection**: The server receives only AES-256-GCM ciphertext blobs. The encryption key is derived client-side via HKDF and is never transmitted over the wire or stored on the server. Even under full server database compromise, attacker cannot decrypt user passwords.

### 2. Replay Resistance
- **Threat**: Attacker intercepts a valid signed `/store` or `/retrieve` request over the wire and replays it later.
- **Protection**: Nonce must be strictly greater than the server's persisted `LastNonce`. Replayed requests fail with `409 replayed_nonce`.

### 3. Request Tampering & Integrity
- **Threat**: Attacker modifies the payload, email, or nonce in transit.
- **Protection**: The ECDSA signature covers the full tuple `(email, rawPayloadBytes, nonce)`. Modifying any byte invalidates the signature (`400 invalid_signature`).

### 4. Identity Binding
- **Threat**: Attacker signs a valid payload using their own keypair and attaches a victim's email address.
- **Protection**: The server retrieves the public key associated with the requested `email` from storage and verifies against that registered key. An unauthorized key produces a signature verification failure.

---

## 5. Known Limitations & Exercise Simplifications

As permitted by the take-home prompt, certain elements are simplified for clarity and evaluation:
1. **Mocked Email Verification**: The verification token is returned in the `POST /register` response rather than dispatched via SMTP. A production system would deliver an out-of-band email containing a time-limited token.
2. **Single-Vault Overwrite**: `POST /store` updates a single latest backup snapshot per account. Production password managers may maintain encrypted version history or delta syncs.
3. **Password Stretching Algorithm**: PBKDF2-HMAC-SHA256 was selected because it is standard and built-in across .NET BCL and WebCrypto without external native binary dependencies. In production, **Argon2id** is preferred for memory hardness against GPU/ASIC attacks.
4. **Deterministic P-256 Scalar Derivation**: Deriving private scalar $D$ directly from 32-byte HKDF output without rejection sampling against the curve order $n$ is standard for exercises, but production systems should use RFC 6979 / hash-to-curve or retry counters.
5. **No Password Reset by Design**: Because recovery depends entirely on the master password, forgetting the master password makes the vault unrecoverable. This is the intended security model of zero-knowledge architectures.

---

## 6. Production Roadmap

To scale this service to production:
- **Argon2id Password Hashing**: Integrate Argon2id (e.g., $m=64\text{MB}, t=3, p=4$) client-side.
- **Rate Limiting & Abuse Prevention**: IP and account rate limiting on `/register` and `/verify` via sliding window or token bucket (e.g. Redis) to prevent brute-force attacks.
- **Token Expiration & Out-of-Band Delivery**: Store verification tokens with cryptographic hashes (SHA-256) and a 15-minute TTL; send via transactional email provider (SendGrid / AWS SES).
- **Key Rotation**: Implement a re-encryption ceremony where the client derives a new keypair, requests the current vault under the old key, decrypts, re-encrypts under the new key, and updates the public key via a signed migration envelope.
- **Horizontal Scaling & Database Clustering**: Replace SQLite with PostgreSQL / Spanner with optimistic concurrency control (`xmin` / row versioning) on `LastNonce`.
- **Audit Logging**: Structured security telemetry tracking signature failures and nonce conflicts to detect active brute-force or replay attacks.

---

## 7. How to Build & Run

### Running the .NET 10 C# Solution

```bash
# 1. Restore & Build
dotnet restore VaultBackup.sln
dotnet build VaultBackup.sln

# 2. Start the Server (Terminal 1)
cd VaultServer
dotnet run

# 3. Run the Client Demonstration (Terminal 2)
cd VaultClient
dotnet run
```

---

## 8. AI-Assistance Disclosure

- **Architecture, Protocol Design, and Cryptographic Pipeline**: Formulated using standard cryptographic primitives (NIST P-256, PBKDF2-HMAC-SHA256, HKDF-SHA256, AES-256-GCM).
- **Tooling Assistance**: Generative AI tools were utilized to assist in drafting boilerplate C# / .NET 10 class files, SQLite schemas, and documentation. All code, security constraints, and design decisions have been thoroughly reviewed for correctness and compliance.
