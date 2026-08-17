using System.Text.Json.Serialization;

namespace VaultShared.Protocol;

/// <summary>
/// The standard request envelope for authenticated requests.
/// </summary>
public record RequestEnvelope
{
    [JsonPropertyName("email")]
    public required string Email { get; init; }

    /// <summary>
    /// Base64 encoded UTF-8 JSON payload.
    /// </summary>
    [JsonPropertyName("payload")]
    public required string Payload { get; init; }

    /// <summary>
    /// Monotonically increasing nonce (e.g. Unix millisecond timestamp).
    /// </summary>
    [JsonPropertyName("nonce")]
    public required long Nonce { get; init; }

    /// <summary>
    /// Base64 encoded ECDSA signature over UTF8(email) || 0x00 || rawPayloadBytes || 0x00 || UTF8(nonce).
    /// </summary>
    [JsonPropertyName("signature")]
    public required string Signature { get; init; }
}

/// <summary>
/// Standard API error response format.
/// </summary>
public record ApiErrorResponse
{
    [JsonPropertyName("error")]
    public required string Error { get; init; }

    [JsonPropertyName("message")]
    public required string Message { get; init; }
}
