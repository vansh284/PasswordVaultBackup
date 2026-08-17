using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using VaultServer.Data;
using VaultShared.Protocol;

namespace VaultServer.Services;

public class AccountService
{
    private readonly VaultDbContext _dbContext;
    private readonly ILogger<AccountService> _logger;

    public AccountService(VaultDbContext dbContext, ILogger<AccountService> logger)
    {
        _dbContext = dbContext;
        _logger = logger;
    }

    /// <summary>
    /// Registers a new account with email and public key in PEM format. Creates in unverified state.
    /// </summary>
    public async Task<(bool Success, string? ErrorCode, string? Message, string? VerificationToken)> RegisterAsync(RegisterRequest request)
    {
        if (string.IsNullOrWhiteSpace(request.Email) || !request.Email.Contains('@'))
        {
            return (false, "malformed_request", "A valid email address is required.", null);
        }

        if (string.IsNullOrWhiteSpace(request.PublicKeyPem) || !request.PublicKeyPem.Contains("BEGIN PUBLIC KEY"))
        {
            return (false, "malformed_request", "A valid PEM-encoded public key is required.", null);
        }

        string normalizedEmail = request.Email.Trim().ToLowerInvariant();
        string token = Convert.ToHexString(RandomNumberGenerator.GetBytes(16)).ToLowerInvariant(); // Mock 32-char hex token
        string now = DateTimeOffset.UtcNow.ToString("O");

        using var conn = _dbContext.CreateConnection();
        await conn.OpenAsync();

        using var checkCmd = conn.CreateCommand();
        checkCmd.CommandText = "SELECT COUNT(1) FROM Accounts WHERE Email = @email";
        checkCmd.Parameters.AddWithValue("@email", normalizedEmail);
        long count = (long)(await checkCmd.ExecuteScalarAsync() ?? 0L);

        if (count > 0)
        {
            return (false, "email_already_registered", "This email address is already registered.", null);
        }

        using var insertCmd = conn.CreateCommand();
        insertCmd.CommandText = @"
            INSERT INTO Accounts (Email, PublicKeyPem, Verified, VerificationToken, LastNonce, CreatedAt)
            VALUES (@email, @pem, 0, @token, 0, @createdAt);
        ";
        insertCmd.Parameters.AddWithValue("@email", normalizedEmail);
        insertCmd.Parameters.AddWithValue("@pem", request.PublicKeyPem.Trim());
        insertCmd.Parameters.AddWithValue("@token", token);
        insertCmd.Parameters.AddWithValue("@createdAt", now);

        await insertCmd.ExecuteNonQueryAsync();

        _logger.LogInformation("Account registered for {Email}. Mock verification token: {Token}", normalizedEmail, token);

        return (true, null, null, token);
    }

    /// <summary>
    /// Looks up account by email.
    /// </summary>
    public async Task<AccountRecord?> GetAccountAsync(string email)
    {
        string normalizedEmail = email.Trim().ToLowerInvariant();
        using var conn = _dbContext.CreateConnection();
        await conn.OpenAsync();

        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT Email, PublicKeyPem, Verified, VerificationToken, LastNonce, CreatedAt FROM Accounts WHERE Email = @email";
        cmd.Parameters.AddWithValue("@email", normalizedEmail);

        using var reader = await cmd.ExecuteReaderAsync();
        if (await reader.ReadAsync())
        {
            return new AccountRecord(
                Email: reader.GetString(0),
                PublicKeyPem: reader.GetString(1),
                Verified: reader.GetInt32(2) == 1,
                VerificationToken: reader.IsDBNull(3) ? null : reader.GetString(3),
                LastNonce: reader.GetInt64(4),
                CreatedAt: reader.GetString(5)
            );
        }

        return null;
    }

    /// <summary>
    /// Verifies account with token and updates LastNonce in a single atomic transaction.
    /// </summary>
    public async Task<(bool Success, string? ErrorCode, string? Message)> VerifyAccountAsync(string email, string token, long nonce)
    {
        string normalizedEmail = email.Trim().ToLowerInvariant();
        using var conn = _dbContext.CreateConnection();
        await conn.OpenAsync();

        using var tx = conn.BeginTransaction();

        using var selectCmd = conn.CreateCommand();
        selectCmd.Transaction = tx;
        selectCmd.CommandText = "SELECT Verified, VerificationToken, LastNonce FROM Accounts WHERE Email = @email";
        selectCmd.Parameters.AddWithValue("@email", normalizedEmail);

        using var reader = await selectCmd.ExecuteReaderAsync();
        if (!await reader.ReadAsync())
        {
            return (false, "account_not_found", "Account does not exist.");
        }

        bool isVerified = reader.GetInt32(0) == 1;
        string? expectedToken = reader.IsDBNull(1) ? null : reader.GetString(1);
        long currentLastNonce = reader.GetInt64(2);
        reader.Close();

        if (isVerified)
        {
            return (false, "token_already_used", "Account has already been verified.");
        }

        if (!string.Equals(expectedToken, token, StringComparison.OrdinalIgnoreCase))
        {
            return (false, "invalid_token", "The provided verification token is invalid.");
        }

        using var updateCmd = conn.CreateCommand();
        updateCmd.Transaction = tx;
        updateCmd.CommandText = "UPDATE Accounts SET Verified = 1, VerificationToken = NULL, LastNonce = @nonce WHERE Email = @email";
        updateCmd.Parameters.AddWithValue("@nonce", nonce);
        updateCmd.Parameters.AddWithValue("@email", normalizedEmail);

        await updateCmd.ExecuteNonQueryAsync();
        await tx.CommitAsync();

        _logger.LogInformation("Account {Email} successfully verified.", normalizedEmail);
        return (true, null, null);
    }
}
