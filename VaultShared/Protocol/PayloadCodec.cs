using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using VaultShared.Crypto;

namespace VaultShared.Protocol;

/// <summary>
/// Codec utilities for serializing, base64 encoding, and packing request envelopes.
/// </summary>
public static class PayloadCodec
{
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        WriteIndented = false
    };

    /// <summary>
    /// Serializes an object to JSON and returns its UTF-8 raw bytes.
    /// </summary>
    public static byte[] ToJsonBytes<T>(T payload)
    {
        return JsonSerializer.SerializeToUtf8Bytes(payload, JsonOptions);
    }

    /// <summary>
    /// Encodes UTF-8 JSON bytes to Base64.
    /// </summary>
    public static string ToBase64(byte[] bytes)
    {
        return Convert.ToBase64String(bytes);
    }

    /// <summary>
    /// Decodes Base64 to raw bytes.
    /// </summary>
    public static byte[] FromBase64(string base64)
    {
        return Convert.FromBase64String(base64);
    }

    /// <summary>
    /// Deserializes a Base64-encoded JSON payload into type T.
    /// </summary>
    public static T? DeserializePayload<T>(string payloadBase64)
    {
        byte[] bytes = FromBase64(payloadBase64);
        return JsonSerializer.Deserialize<T>(bytes, JsonOptions);
    }

    /// <summary>
    /// Creates a fully signed RequestEnvelope for a given payload object.
    /// </summary>
    public static RequestEnvelope CreateSignedEnvelope<T>(string email, ECDsa privateKey, T payload, long? customNonce = null)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(email);
        ArgumentNullException.ThrowIfNull(privateKey);
        ArgumentNullException.ThrowIfNull(payload);

        byte[] rawPayloadBytes = ToJsonBytes(payload);
        string payloadBase64 = ToBase64(rawPayloadBytes);

        // Default nonce is current Unix epoch milliseconds
        long nonce = customNonce ?? DateTimeOffset.UtcNow.ToUnixTimeMilliseconds();

        byte[] canonicalMessage = SigningService.BuildSignedMessage(email, rawPayloadBytes, nonce);
        byte[] signatureBytes = SigningService.Sign(privateKey, canonicalMessage);
        string signatureBase64 = ToBase64(signatureBytes);

        return new RequestEnvelope
        {
            Email = email.Trim().ToLowerInvariant(),
            Payload = payloadBase64,
            Nonce = nonce,
            Signature = signatureBase64
        };
    }
}
