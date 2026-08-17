using Microsoft.Data.Sqlite;

namespace VaultServer.Data;

public record AccountRecord(
    string Email,
    string PublicKeyPem,
    bool Verified,
    string? VerificationToken,
    long LastNonce,
    string CreatedAt
);

public record VaultRecord(
    string Email,
    string EncryptedBlobBase64,
    string UpdatedAt
);

public class VaultDbContext
{
    private readonly string _connectionString;

    public VaultDbContext(IConfiguration configuration)
    {
        _connectionString = configuration.GetConnectionString("VaultDatabase") ?? "Data Source=vault.db";
    }

    public SqliteConnection CreateConnection()
    {
        var connection = new SqliteConnection(_connectionString);
        return connection;
    }

    public void InitializeDatabase()
    {
        using var connection = CreateConnection();
        connection.Open();

        // Enable WAL mode for high performance concurrency
        using var walCmd = connection.CreateCommand();
        walCmd.CommandText = "PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;";
        walCmd.ExecuteNonQuery();

        string schemaPath = Path.Combine(AppContext.BaseDirectory, "Data", "schema.sql");
        string sql;
        if (File.Exists(schemaPath))
        {
            sql = File.ReadAllText(schemaPath);
        }
        else
        {
            sql = @"
                CREATE TABLE IF NOT EXISTS Accounts (
                    Email TEXT PRIMARY KEY COLLATE NOCASE,
                    PublicKeyPem TEXT NOT NULL,
                    Verified INTEGER NOT NULL DEFAULT 0,
                    VerificationToken TEXT,
                    LastNonce INTEGER NOT NULL DEFAULT 0,
                    CreatedAt TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS Vaults (
                    Email TEXT PRIMARY KEY COLLATE NOCASE REFERENCES Accounts(Email) ON DELETE CASCADE,
                    EncryptedBlobBase64 TEXT NOT NULL,
                    UpdatedAt TEXT NOT NULL
                );
            ";
        }

        using var cmd = connection.CreateCommand();
        cmd.CommandText = sql;
        cmd.ExecuteNonQuery();
    }
}
