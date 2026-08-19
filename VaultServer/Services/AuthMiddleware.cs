using System.Security.Cryptography;
using System.Text.Json;
using VaultServer.Data;
using VaultShared.Crypto;
using VaultShared.Protocol;

namespace VaultServer.Services;

public record AuthValidationResult(
    bool IsValid,
    int StatusCode,
    string? ErrorCode,
    string? Message,
    AccountRecord? Account,
    byte[]? RawPayloadBytes
);

/// <summary>
/// Handles authentication pipeline: envelope parsing, account lookup, verification check,
/// nonce replay protection, and canonical ECDSA P-256 signature verification.
/// </summary>
public class AuthValidator
{
    private readonly AccountService _accountService;
    private readonly ILogger<AuthValidator> _logger;

    public AuthValidator(AccountService accountService, ILogger<AuthValidator> logger)
    {
        _accountService = accountService;
        _logger = logger;
    }

    public async Task<AuthValidationResult> ValidateRequestAsync(
        RequestEnvelope envelope,
        bool requireVerified = true)
    {
        if (envelope == null ||
            string.IsNullOrWhiteSpace(envelope.Email) ||
            string.IsNullOrWhiteSpace(envelope.Payload) ||
            string.IsNullOrWhiteSpace(envelope.Signature))
        {
            return new AuthValidationResult(false, StatusCodes.Status400BadRequest, "malformed_request", "Envelope is missing required fields.", null, null);
        }

        string email = envelope.Email.Trim().ToLowerInvariant();

        // 1. Look up account (needed to get public key for signature verification)
        var account = await _accountService.GetAccountAsync(email);
        if (account == null)
        {
            return new AuthValidationResult(false, StatusCodes.Status404NotFound, "account_not_found", $"No account found with email '{email}'.", null, null);
        }

        // 2. Decode base64 payload bytes and signature
        byte[] rawPayloadBytes;
        byte[] signatureBytes;
        try
        {
            rawPayloadBytes = PayloadCodec.FromBase64(envelope.Payload);
            signatureBytes = PayloadCodec.FromBase64(envelope.Signature);
        }
        catch (FormatException)
        {
            return new AuthValidationResult(false, StatusCodes.Status400BadRequest, "malformed_request", "Payload or signature is not valid Base64.", account, null);
        }

        // 3. Build canonical message: UTF8(email) || 0x00 || rawPayloadBytes || 0x00 || UTF8(nonce)
        byte[] canonicalMessage = SigningService.BuildSignedMessage(email, rawPayloadBytes, envelope.Nonce);

        // 4. Verify signature against stored ECDSA public key
        // This MUST happen before checking verification status or nonce to avoid leaking account state
        try
        {
            using var publicKey = SigningService.ImportPublicKeyPem(account.PublicKeyPem);
            bool verified = SigningService.Verify(publicKey, canonicalMessage, signatureBytes);

            if (!verified)
            {
                _logger.LogWarning("Invalid ECDSA signature for {Email}", email);
                return new AuthValidationResult(false, StatusCodes.Status400BadRequest, "invalid_signature", "The cryptographic signature could not be verified against the registered public key.", account, null);
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to verify signature for {Email}", email);
            return new AuthValidationResult(false, StatusCodes.Status400BadRequest, "invalid_signature", "Signature verification failed.", account, null);
        }

        // 5. Check verification status if required
        if (requireVerified && !account.Verified)
        {
            return new AuthValidationResult(false, StatusCodes.Status403Forbidden, "account_unverified", "Email address has not been verified.", account, null);
        }

        // 6. Monotonic nonce replay protection: nonce must be strictly greater than LastNonce
        if (envelope.Nonce <= account.LastNonce)
        {
            _logger.LogWarning("Replayed nonce detected for {Email}. Received {Nonce}, current LastNonce is {LastNonce}", email, envelope.Nonce, account.LastNonce);
            return new AuthValidationResult(false, StatusCodes.Status409Conflict, "replayed_nonce", $"Nonce {envelope.Nonce} is not strictly greater than last recorded nonce {account.LastNonce}.", account, null);
        }

        return new AuthValidationResult(true, StatusCodes.Status200OK, null, null, account, rawPayloadBytes);
    }
}
