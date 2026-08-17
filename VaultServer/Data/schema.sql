-- VaultBackup Database Schema (SQLite)

CREATE TABLE IF NOT EXISTS Accounts (
    Email               TEXT PRIMARY KEY COLLATE NOCASE,
    PublicKeyPem        TEXT NOT NULL,
    Verified            INTEGER NOT NULL DEFAULT 0,
    VerificationToken   TEXT,
    LastNonce           INTEGER NOT NULL DEFAULT 0,
    CreatedAt           TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS Vaults (
    Email               TEXT PRIMARY KEY COLLATE NOCASE REFERENCES Accounts(Email) ON DELETE CASCADE,
    EncryptedBlobBase64 TEXT NOT NULL,
    UpdatedAt           TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_accounts_verified ON Accounts(Email, Verified);
