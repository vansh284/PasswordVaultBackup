using System.Security.Cryptography;
using System.Text;

namespace VaultShared.Crypto;

/// <summary>
/// Handles deterministic derivation of ECDSA authentication keypair and AES-256 vault encryption key
/// from the user's master password and email address.
/// </summary>
public static class KeyDerivation
{
    private const int Pbkdf2Iterations = 600_000;
    private const int MasterSecretLength = 32;
    private const int DerivedKeyLength = 32;

    private static readonly byte[] SigningInfo = Encoding.UTF8.GetBytes("vault-backup:signing-key:v1");
    private static readonly byte[] EncryptionInfo = Encoding.UTF8.GetBytes("vault-backup:encryption-key:v1");

    /// <summary>
    /// Derives both the ECDSA P-256 signing key and AES-256 encryption key deterministically.
    /// </summary>
    /// <param name="email">User's email address (used as PBKDF2 salt, normalized to lowercase).</param>
    /// <param name="masterPassword">User's master password string.</param>
    /// <returns>A tuple containing the initialized ECDsa instance and the 32-byte AES key.</returns>
    public static (ECDsa SigningKey, byte[] EncryptionKey) DeriveKeys(string email, string masterPassword)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        ArgumentException.ThrowIfNullOrWhiteSpace(masterPassword);

        // 1. Password stretching using PBKDF2-HMAC-SHA256 (OWASP 2023 guidelines)
        byte[] salt = Encoding.UTF8.GetBytes(email.Trim().ToLowerInvariant());
        byte[] passwordBytes = Encoding.UTF8.GetBytes(masterPassword);

        byte[] masterSecret = Rfc2898DeriveBytes.Pbkdf2(
            passwordBytes,
            salt,
            Pbkdf2Iterations,
            HashAlgorithmName.SHA256,
            MasterSecretLength
        );

        // 2. Domain separation using HKDF-SHA256
        byte[] signingSeed = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            ikm: masterSecret,
            outputLength: DerivedKeyLength,
            salt: null,
            info: SigningInfo
        );

        byte[] encryptionKey = HKDF.DeriveKey(
            HashAlgorithmName.SHA256,
            ikm: masterSecret,
            outputLength: DerivedKeyLength,
            salt: null,
            info: EncryptionInfo
        );

        // 3. Construct deterministic NIST P-256 key from derived private scalar D
        var ecParams = new ECParameters
        {
            Curve = ECCurve.NamedCurves.nistP256,
            D = signingSeed
        };

        var ecdsa = ECDsa.Create(ecParams);

        // Securely wipe intermediate secrets from memory
        CryptographicOperations.ZeroMemory(masterSecret);
        CryptographicOperations.ZeroMemory(signingSeed);

        return (ecdsa, encryptionKey);
    }
}
