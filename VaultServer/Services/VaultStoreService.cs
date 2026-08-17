using Microsoft.Data.Sqlite;
using VaultServer.Data;
using VaultShared.Protocol;

namespace VaultServer.Services;

public class VaultStoreService
{
    private readonly VaultDbContext _dbContext;
    private readonly ILogger<VaultStoreService> _logger;

    public VaultStoreService(VaultDbContext dbContext, ILogger<VaultStoreService> logger)
    {
        _dbContext = dbContext;
        _logger = logger;
    }

    /// <summary>
    /// Stores or overwrites the encrypted vault blob for an account, and updates LastNonce in a single transaction.
    /// </summary>
    public async Task<(bool Success, string? ErrorCode, string? Message, string? StoredAt)> StoreVaultAsync(string email, string encryptedBlobBase64, long nonce)
    {
        if (string.IsNullOrWhiteSpace(encryptedBlobBase64))
        {
            return (false, "malformed_request", "Encrypted vault payload cannot be empty.", null);
        }

        string normalizedEmail = email.Trim().ToLowerInvariant();
        string now = DateTimeOffset.UtcNow.ToString("O");

        using var conn = _dbContext.CreateConnection();
        await conn.OpenAsync();

        using var tx = conn.BeginTransaction();

        // 1. Update LastNonce on account
        using var nonceCmd = conn.CreateCommand();
        nonceCmd.Transaction = tx;
        nonceCmd.CommandText = "UPDATE Accounts SET LastNonce = @nonce WHERE Email = @email";
        nonceCmd.Parameters.AddWithValue("@nonce", nonce);
        nonceCmd.Parameters.AddWithValue("@email", normalizedEmail);
        await nonceCmd.ExecuteNonQueryAsync();

        // 2. Upsert encrypted vault blob
        using var upsertCmd = conn.CreateCommand();
        upsertCmd.Transaction = tx;
        upsertCmd.CommandText = @"
            INSERT INTO Vaults (Email, EncryptedBlobBase64, UpdatedAt)
            VALUES (@email, @blob, @updatedAt)
            ON CONFLICT(Email) DO UPDATE SET
                EncryptedBlobBase64 = excluded.EncryptedBlobBase64,
                UpdatedAt = excluded.UpdatedAt;
        ";
        upsertCmd.Parameters.AddWithValue("@email", normalizedEmail);
        upsertCmd.Parameters.AddWithValue("@blob", encryptedBlobBase64);
        upsertCmd.Parameters.AddWithValue("@updatedAt", now);

        await upsertCmd.ExecuteNonQueryAsync();
        await tx.CommitAsync();

        _logger.LogInformation("Stored encrypted vault for {Email} (nonce: {Nonce})", normalizedEmail, nonce);
        return (true, null, null, now);
    }

    /// <summary>
    /// Retrieves the encrypted vault blob for an account, and updates LastNonce in a single transaction.
    /// </summary>
    public async Task<(bool Success, string? ErrorCode, string? Message, RetrieveResponse? Result)> RetrieveVaultAsync(string email, long nonce)
    {
        string normalizedEmail = email.Trim().ToLowerInvariant();

        using var conn = _dbContext.CreateConnection();
        await conn.OpenAsync();

        using var tx = conn.BeginTransaction();

        // 1. Fetch vault
        using var selectCmd = conn.CreateCommand();
        selectCmd.Transaction = tx;
        selectCmd.CommandText = "SELECT EncryptedBlobBase64, UpdatedAt FROM Vaults WHERE Email = @email";
        selectCmd.Parameters.AddWithValue("@email", normalizedEmail);

        using var reader = await selectCmd.ExecuteReaderAsync();
        if (!await reader.ReadAsync())
        {
            return (false, "vault_not_found", "No backup vault found for this account.", null);
        }

        string blob = reader.GetString(0);
        string updatedAt = reader.GetString(1);
        reader.Close();

        // 2. Advance LastNonce
        using var nonceCmd = conn.CreateCommand();
        nonceCmd.Transaction = tx;
        nonceCmd.CommandText = "UPDATE Accounts SET LastNonce = @nonce WHERE Email = @email";
        nonceCmd.Parameters.AddWithValue("@nonce", nonce);
        nonceCmd.Parameters.AddWithValue("@email", normalizedEmail);
        await nonceCmd.ExecuteNonQueryAsync();

        await tx.CommitAsync();

        _logger.LogInformation("Retrieved encrypted vault for {Email} (nonce: {Nonce})", normalizedEmail, nonce);
        return (true, null, null, new RetrieveResponse { Vault = blob, UpdatedAt = updatedAt });
    }
}
