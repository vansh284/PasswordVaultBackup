using System.Security.Cryptography;
using System.Text;

namespace VaultShared.Crypto;

/// <summary>
/// Provides client-side authenticated symmetric encryption and decryption of vault data using AES-256-GCM.
/// Ciphertext format: Nonce (12 bytes) || AuthTag (16 bytes) || Ciphertext (N bytes), encoded as Base64.
/// </summary>
public static class VaultCipher
{
    public const int NonceSizeBytes = 12;
    public const int TagSizeBytes = 16;

    /// <summary>
    /// Encrypts plaintext string using AES-256-GCM with a freshly generated random 12-byte nonce.
    /// </summary>
    /// <param name="key">32-byte AES key derived via HKDF.</param>
    /// <param name="plaintext">Plaintext JSON string of the vault content.</param>
    /// <returns>Base64 encoded string representing [Nonce || Tag || Ciphertext].</returns>
    public static string Encrypt(byte[] key, string plaintext)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != 32)
            throw new ArgumentException("AES-256 key must be exactly 32 bytes.", nameof(key));
        ArgumentNullException.ThrowIfNull(plaintext);

        byte[] plaintextBytes = Encoding.UTF8.GetBytes(plaintext);
        byte[] nonce = new byte[NonceSizeBytes];
        // Extremely low probability of nonce collision with 96 bytes of randomness, to be extra safe, I would check for collisions in a database or use a counter-based nonce.
        RandomNumberGenerator.Fill(nonce);

        byte[] tag = new byte[TagSizeBytes];
        byte[] ciphertext = new byte[plaintextBytes.Length];

        using (var aes = new AesGcm(key, TagSizeBytes))
        {
            aes.Encrypt(nonce, plaintextBytes, ciphertext, tag);
        }

        // Pack: nonce (12) || tag (16) || ciphertext (N)
        byte[] packed = new byte[NonceSizeBytes + TagSizeBytes + ciphertext.Length];
        Buffer.BlockCopy(nonce, 0, packed, 0, NonceSizeBytes);
        Buffer.BlockCopy(tag, 0, packed, NonceSizeBytes, TagSizeBytes);
        Buffer.BlockCopy(ciphertext, 0, packed, NonceSizeBytes + TagSizeBytes, ciphertext.Length);

        return Convert.ToBase64String(packed);
    }

    /// <summary>
    /// Decrypts the Base64 encoded blob [Nonce || Tag || Ciphertext] using AES-256-GCM.
    /// </summary>
    /// <param name="key">32-byte AES key derived via HKDF.</param>
    /// <param name="encryptedBlobBase64">Base64 encoded ciphertext blob.</param>
    /// <returns>Decrypted UTF-8 plaintext string.</returns>
    public static string Decrypt(byte[] key, string encryptedBlobBase64)
    {
        ArgumentNullException.ThrowIfNull(key);
        if (key.Length != 32)
            throw new ArgumentException("AES-256 key must be exactly 32 bytes.", nameof(key));
        ArgumentException.ThrowIfNullOrWhiteSpace(encryptedBlobBase64);

        byte[] packed = Convert.FromBase64String(encryptedBlobBase64);
        if (packed.Length < NonceSizeBytes + TagSizeBytes)
            throw new CryptographicException("Encrypted blob is too short to contain valid nonce and authentication tag.");

        byte[] nonce = new byte[NonceSizeBytes];
        byte[] tag = new byte[TagSizeBytes];
        int cipherLength = packed.Length - NonceSizeBytes - TagSizeBytes;
        byte[] ciphertext = new byte[cipherLength];
        byte[] plaintextBytes = new byte[cipherLength];

        Buffer.BlockCopy(packed, 0, nonce, 0, NonceSizeBytes);
        Buffer.BlockCopy(packed, NonceSizeBytes, tag, 0, TagSizeBytes);
        Buffer.BlockCopy(packed, NonceSizeBytes + TagSizeBytes, ciphertext, 0, cipherLength);

        using (var aes = new AesGcm(key, TagSizeBytes))
        {
            aes.Decrypt(nonce, ciphertext, tag, plaintextBytes);
        }

        return Encoding.UTF8.GetString(plaintextBytes);
    }
}
