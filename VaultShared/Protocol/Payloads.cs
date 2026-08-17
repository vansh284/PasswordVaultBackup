using System.Text.Json.Serialization;

namespace VaultShared.Protocol;

/// <summary>
/// Unsigned body for the POST /register endpoint.
/// </summary>
public record RegisterRequest
{
    [JsonPropertyName("email")]
    public required string Email { get; init; }

    [JsonPropertyName("publicKeyPem")]
    public required string PublicKeyPem { get; init; }
}

/// <summary>
/// Response from POST /register in dev mode.
/// </summary>
public record RegisterResponse
{
    [JsonPropertyName("message")]
    public string Message { get; init; } = "Account created. Please complete email verification.";

    [JsonPropertyName("email")]
    public required string Email { get; init; }

    [JsonPropertyName("verificationToken")]
    public required string VerificationToken { get; init; }
}

/// <summary>
/// Payload for POST /verify inside signed envelope.
/// </summary>
public record VerifyPayload
{
    [JsonPropertyName("type")]
    public string Type { get; init; } = "verify";

    [JsonPropertyName("token")]
    public required string Token { get; init; }
}

/// <summary>
/// Payload for POST /store inside signed envelope.
/// </summary>
public record StorePayload
{
    [JsonPropertyName("type")]
    public string Type { get; init; } = "store";

    [JsonPropertyName("vault")]
    public required string Vault { get; init; }
}

/// <summary>
/// Payload for POST /retrieve inside signed envelope.
/// </summary>
public record RetrievePayload
{
    [JsonPropertyName("type")]
    public string Type { get; init; } = "retrieve";
}

/// <summary>
/// Response for POST /retrieve.
/// </summary>
public record RetrieveResponse
{
    [JsonPropertyName("vault")]
    public required string Vault { get; init; }

    [JsonPropertyName("updatedAt")]
    public required string UpdatedAt { get; init; }
}

/// <summary>
/// Representation of a sample password entry in the client-side vault.
/// </summary>
public record VaultItem(
    [property: JsonPropertyName("site")] string Site,
    [property: JsonPropertyName("username")] string Username,
    [property: JsonPropertyName("password")] string Password,
    [property: JsonPropertyName("notes")] string? Notes = null
);
