using System.Security.Cryptography;
using System.Text;

namespace VaultShared.Crypto;

/// <summary>
/// Handles ECDSA message signing and signature verification with unambiguous canonical byte construction.
/// </summary>
public static class SigningService
{
    private static readonly byte Separator = 0x00;

    /// <summary>
    /// Constructs the unambiguous canonical byte array to be signed:
    /// UTF8(email) || 0x00 || rawPayloadBytes || 0x00 || UTF8(nonce.ToString())
    /// </summary>
    public static byte[] BuildSignedMessage(string email, byte[] rawPayloadBytes, long nonce)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        ArgumentNullException.ThrowIfNull(rawPayloadBytes);

        byte[] emailBytes = Encoding.UTF8.GetBytes(email.Trim().ToLowerInvariant());
        byte[] nonceBytes = Encoding.UTF8.GetBytes(nonce.ToString());

        int totalLen = emailBytes.Length + 1 + rawPayloadBytes.Length + 1 + nonceBytes.Length;
        byte[] message = new byte[totalLen];

        int offset = 0;
        Buffer.BlockCopy(emailBytes, 0, message, offset, emailBytes.Length);
        offset += emailBytes.Length;

        message[offset++] = Separator;

        Buffer.BlockCopy(rawPayloadBytes, 0, message, offset, rawPayloadBytes.Length);
        offset += rawPayloadBytes.Length;

        message[offset++] = Separator;

        Buffer.BlockCopy(nonceBytes, 0, message, offset, nonceBytes.Length);

        return message;
    }

    /// <summary>
    /// Signs the canonical message using ECDSA P-256 with SHA-256. Returns IEEE P1363 or DER signature bytes.
    /// In .NET, SignData with DSASignatureFormat.IeeeP1363 or default DER format produces a valid standard signature.
    /// </summary>
    public static byte[] Sign(ECDsa privateKey, byte[] canonicalMessage)
    {
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(canonicalMessage);

        return privateKey.SignData(canonicalMessage, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
    }

    /// <summary>
    /// Verifies the signature of the canonical message against the provided public key.
    /// </summary>
    public static bool Verify(ECDsa publicKey, byte[] canonicalMessage, byte[] signature)
    {
        ArgumentNullException.ThrowIfNull(publicKey);
        ArgumentNullException.ThrowIfNull(canonicalMessage);
        ArgumentNullException.ThrowIfNull(signature);

        return publicKey.VerifyData(canonicalMessage, signature, HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
    }

    /// <summary>
    /// Exports the ECDSA public key in standard PEM (SubjectPublicKeyInfo) format.
    /// </summary>
    public static string ExportPublicKeyPem(this ECDsa ecdsa)
    {
        return ecdsa.ExportSubjectPublicKeyInfoPem();
    }

    /// <summary>
    /// Imports an ECDSA public key from standard PEM format.
    /// </summary>
    public static ECDsa ImportPublicKeyPem(string pem)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(pem);
        var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(pem);
        return ecdsa;
    }
}
