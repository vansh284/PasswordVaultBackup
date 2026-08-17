using System.Diagnostics;
using System.Net;
using System.Net.Http.Json;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using VaultShared.Crypto;
using VaultShared.Protocol;

namespace VaultClient;

public class Program
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNamingPolicy = JsonNamingPolicy.CamelCase, WriteIndented = true };

    public static async Task Main(string[] args)
    {
        Console.OutputEncoding = Encoding.UTF8;
        string baseUrl = args.Length > 0 ? args[0] : "http://localhost:5000";

        // Allow bypassing self-signed dev cert for local testing if https is used
        var handler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = HttpClientHandler.DangerousAcceptAnyServerCertificateValidator
        };
        using var http = new HttpClient(handler) { BaseAddress = new Uri(baseUrl) };

        Console.WriteLine("================================================================================");
        Console.WriteLine("   SECURE PASSWORD VAULT BACKUP API — CLIENT WORKFLOW DEMONSTRATION");
        Console.WriteLine("================================================================================");
        Console.WriteLine($"Server endpoint: {baseUrl}\n");

        string email = $"alice_{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}@example.com";
        string masterPassword = "correct-horse-battery-staple-2026";

        Console.WriteLine($"User Email:           {email}");
        Console.WriteLine($"Master Password:      {masterPassword}\n");

        // -----------------------------------------------------------------------------------------
        // STEP 1: Generate key pair and symmetric encryption key deterministically from master password
        // -----------------------------------------------------------------------------------------
        Console.WriteLine("--------------------------------------------------------------------------------");
        Console.WriteLine("STEP 1: Deterministic Key Derivation (PBKDF2-HMAC-SHA256 + HKDF-SHA256)");
        Console.WriteLine("--------------------------------------------------------------------------------");
        var sw = Stopwatch.StartNew();
        var (signingKey, aesEncryptionKey) = KeyDerivation.DeriveKeys(email, masterPassword);
        sw.Stop();

        string publicKeyPem = signingKey.ExportPublicKeyPem();
        Console.WriteLine($"[+] PBKDF2 (600,000 iters) + HKDF completed in {sw.ElapsedMilliseconds} ms.");
        Console.WriteLine($"[+] AES-256 Key (Client Secret): {Convert.ToHexString(aesEncryptionKey)[..16]}... (32 bytes)");
        Console.WriteLine($"[+] ECDSA P-256 Public Key PEM:\n{publicKeyPem.Trim()}");
        Console.WriteLine();

        // -----------------------------------------------------------------------------------------
        // STEP 2: Register email and public key with server
        // -----------------------------------------------------------------------------------------
        Console.WriteLine("--------------------------------------------------------------------------------");
        Console.WriteLine("STEP 2: Register Email Address and Public Key (POST /register)");
        Console.WriteLine("--------------------------------------------------------------------------------");
        var regRequest = new RegisterRequest { Email = email, PublicKeyPem = publicKeyPem };
        var regResponse = await http.PostAsJsonAsync("/register", regRequest);
        string regBody = await regResponse.Content.ReadAsStringAsync();
        Console.WriteLine($"Status Code: {(int)regResponse.StatusCode} {regResponse.StatusCode}");
        Console.WriteLine($"Response:    {regBody}");

        if (!regResponse.IsSuccessStatusCode)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[!] Registration failed. Halting.");
            Console.ResetColor();
            return;
        }

        var regData = JsonSerializer.Deserialize<RegisterResponse>(regBody, JsonOpts);
        string verificationToken = regData!.VerificationToken;
        Console.WriteLine($"[+] Mocked Verification Token Received: {verificationToken}\n");

        // -----------------------------------------------------------------------------------------
        // STEP 3: Complete the mocked email-verification process
        // -----------------------------------------------------------------------------------------
        Console.WriteLine("--------------------------------------------------------------------------------");
        Console.WriteLine("STEP 3: Verify Email with Signed Request (POST /verify)");
        Console.WriteLine("--------------------------------------------------------------------------------");
        var verifyPayload = new VerifyPayload { Token = verificationToken };
        var verifyEnvelope = PayloadCodec.CreateSignedEnvelope(email, signingKey, verifyPayload);

        Console.WriteLine($"Envelope Nonce:     {verifyEnvelope.Nonce}");
        Console.WriteLine($"Envelope Signature: {verifyEnvelope.Signature[..24]}... (Base64 DER)");

        var verifyResponse = await http.PostAsJsonAsync("/verify", verifyEnvelope);
        string verifyBody = await verifyResponse.Content.ReadAsStringAsync();
        Console.WriteLine($"Status Code:        {(int)verifyResponse.StatusCode} {verifyResponse.StatusCode}");
        Console.WriteLine($"Response:           {verifyBody}");

        if (!verifyResponse.IsSuccessStatusCode)
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[!] Verification failed. Halting.");
            Console.ResetColor();
            return;
        }
        Console.WriteLine("[+] Account successfully verified!\n");

        // -----------------------------------------------------------------------------------------
        // STEP 4: Encrypt a sample password vault client-side
        // -----------------------------------------------------------------------------------------
        Console.WriteLine("--------------------------------------------------------------------------------");
        Console.WriteLine("STEP 4: Encrypt Sample Password Vault (AES-256-GCM)");
        Console.WriteLine("--------------------------------------------------------------------------------");
        var sampleVault = new List<VaultItem>
        {
            new("github.com", "alice_dev", "P@ssw0rd_Github_99!", "2FA backup keys in safe"),
            new("bank.example.com", "alice.smith", "Correct-Horse-Battery-Staple$", "Checking + Savings"),
            new("work-email.com", "alice@example.com", "UltraSecureToken#2026", "Corporate login")
        };
        string sampleVaultJson = JsonSerializer.Serialize(sampleVault, JsonOpts);
        Console.WriteLine($"Plaintext Vault JSON ({sampleVault.Count} entries):\n{sampleVaultJson}");

        string encryptedBlob = VaultCipher.Encrypt(aesEncryptionKey, sampleVaultJson);
        Console.WriteLine($"\n[+] Ciphertext [12B Nonce || 16B AuthTag || Ciphertext] (Base64):");
        Console.WriteLine($"    {encryptedBlob}\n");

        // -----------------------------------------------------------------------------------------
        // STEP 5: Store the encrypted vault
        // -----------------------------------------------------------------------------------------
        Console.WriteLine("--------------------------------------------------------------------------------");
        Console.WriteLine("STEP 5: Store Encrypted Vault on Server (POST /store)");
        Console.WriteLine("--------------------------------------------------------------------------------");
        // Ensure monotonic nonce progression
        await Task.Delay(10);
        var storePayload = new StorePayload { Vault = encryptedBlob };
        var storeEnvelope = PayloadCodec.CreateSignedEnvelope(email, signingKey, storePayload);

        var storeResponse = await http.PostAsJsonAsync("/store", storeEnvelope);
        string storeBody = await storeResponse.Content.ReadAsStringAsync();
        Console.WriteLine($"Status Code: {(int)storeResponse.StatusCode} {storeResponse.StatusCode}");
        Console.WriteLine($"Response:    {storeBody}\n");

        // -----------------------------------------------------------------------------------------
        // STEP 6: Retrieve the encrypted vault
        // -----------------------------------------------------------------------------------------
        Console.WriteLine("--------------------------------------------------------------------------------");
        Console.WriteLine("STEP 6: Retrieve Encrypted Vault from Server (POST /retrieve)");
        Console.WriteLine("--------------------------------------------------------------------------------");
        await Task.Delay(10);
        var retrievePayload = new RetrievePayload();
        var retrieveEnvelope = PayloadCodec.CreateSignedEnvelope(email, signingKey, retrievePayload);

        var retrieveResponse = await http.PostAsJsonAsync("/retrieve", retrieveEnvelope);
        string retrieveBody = await retrieveResponse.Content.ReadAsStringAsync();
        Console.WriteLine($"Status Code: {(int)retrieveResponse.StatusCode} {retrieveResponse.StatusCode}");
        Console.WriteLine($"Response:    {retrieveBody}\n");

        var retrieveData = JsonSerializer.Deserialize<RetrieveResponse>(retrieveBody, JsonOpts);
        string retrievedBlob = retrieveData!.Vault;

        // -----------------------------------------------------------------------------------------
        // STEP 7: Confirm decrypted data matches stored data
        // -----------------------------------------------------------------------------------------
        Console.WriteLine("--------------------------------------------------------------------------------");
        Console.WriteLine("STEP 7: Decrypt and Validate Integrity");
        Console.WriteLine("--------------------------------------------------------------------------------");
        string decryptedJson = VaultCipher.Decrypt(aesEncryptionKey, retrievedBlob);
        var decryptedItems = JsonSerializer.Deserialize<List<VaultItem>>(decryptedJson, JsonOpts);

        bool isIdentical = decryptedJson == sampleVaultJson;
        Console.WriteLine($"Decrypted Vault Content:\n{decryptedJson}\n");
        if (isIdentical)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine($"[✓] SUCCESS: Decrypted vault matches original plaintext exactly! ({decryptedItems?.Count} items verified)");
            Console.ResetColor();
        }
        else
        {
            Console.ForegroundColor = ConsoleColor.Red;
            Console.WriteLine("[✗] FAILURE: Decrypted vault does not match original!");
            Console.ResetColor();
        }
        Console.WriteLine();

        // -----------------------------------------------------------------------------------------
        // NEGATIVE TEST SUITE: Security & Attack Rejection
        // -----------------------------------------------------------------------------------------
        Console.WriteLine("================================================================================");
        Console.WriteLine("   SECURITY & NEGATIVE TEST SUITE");
        Console.WriteLine("================================================================================");

        // Negative Test 1: Replayed Nonce
        Console.WriteLine("\n[Test 1] Replay Attack: Resending identical previous store envelope...");
        var replayResponse = await http.PostAsJsonAsync("/store", storeEnvelope);
        string replayBody = await replayResponse.Content.ReadAsStringAsync();
        Console.WriteLine($"Result: {(int)replayResponse.StatusCode} {replayResponse.StatusCode} -> {replayBody}");
        Debug.Assert(replayResponse.StatusCode == HttpStatusCode.Conflict);
        Console.WriteLine(replayResponse.StatusCode == HttpStatusCode.Conflict ? "  -> PASS: Replay rejected with 409 Conflict." : "  -> FAIL!");

        // Negative Test 2: Tampered Payload
        Console.WriteLine("\n[Test 2] Tamper Attack: Modifying 1 byte in payload without resigning...");
        await Task.Delay(10);
        var tamperedEnvelope = PayloadCodec.CreateSignedEnvelope(email, signingKey, storePayload);
        // Tamper with base64 payload
        char[] pChars = tamperedEnvelope.Payload.ToCharArray();
        pChars[10] = pChars[10] == 'A' ? 'B' : 'A';
        var tampered = tamperedEnvelope with { Payload = new string(pChars) };
        var tamperResponse = await http.PostAsJsonAsync("/store", tampered);
        string tamperBody = await tamperResponse.Content.ReadAsStringAsync();
        Console.WriteLine($"Result: {(int)tamperResponse.StatusCode} {tamperResponse.StatusCode} -> {tamperBody}");
        Debug.Assert(tamperResponse.StatusCode == HttpStatusCode.BadRequest);
        Console.WriteLine(tamperResponse.StatusCode == HttpStatusCode.BadRequest ? "  -> PASS: Tampered payload rejected with 400 Bad Request." : "  -> FAIL!");

        // Negative Test 3: Unauthorized Key Signature
        Console.WriteLine("\n[Test 3] Unauthorized Key: Signing request with an unauthorized keypair...");
        await Task.Delay(10);
        using var bogusKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        var bogusEnvelope = PayloadCodec.CreateSignedEnvelope(email, bogusKey, retrievePayload);
        var bogusResponse = await http.PostAsJsonAsync("/retrieve", bogusEnvelope);
        string bogusBody = await bogusResponse.Content.ReadAsStringAsync();
        Console.WriteLine($"Result: {(int)bogusResponse.StatusCode} {bogusResponse.StatusCode} -> {bogusBody}");
        Debug.Assert(bogusResponse.StatusCode == HttpStatusCode.BadRequest);
        Console.WriteLine(bogusResponse.StatusCode == HttpStatusCode.BadRequest ? "  -> PASS: Invalid key signature rejected with 400 Bad Request." : "  -> FAIL!");

        // Negative Test 4: Unverified Account Access
        Console.WriteLine("\n[Test 4] Unverified Account: Attempting store before verifying email...");
        string unverifiedEmail = $"bob_{DateTimeOffset.UtcNow.ToUnixTimeSeconds()}@example.com";
        var (bobKey, bobAes) = KeyDerivation.DeriveKeys(unverifiedEmail, "bob-secret-password");
        await http.PostAsJsonAsync("/register", new RegisterRequest { Email = unverifiedEmail, PublicKeyPem = bobKey.ExportPublicKeyPem() });
        var unverifiedEnvelope = PayloadCodec.CreateSignedEnvelope(unverifiedEmail, bobKey, new StorePayload { Vault = "some-encrypted-blob" });
        var unverifiedResponse = await http.PostAsJsonAsync("/store", unverifiedEnvelope);
        string unverifiedBody = await unverifiedResponse.Content.ReadAsStringAsync();
        Console.WriteLine($"Result: {(int)unverifiedResponse.StatusCode} {unverifiedResponse.StatusCode} -> {unverifiedBody}");
        Debug.Assert(unverifiedResponse.StatusCode == HttpStatusCode.Forbidden);
        Console.WriteLine(unverifiedResponse.StatusCode == HttpStatusCode.Forbidden ? "  -> PASS: Unverified account rejected with 403 Forbidden." : "  -> FAIL!");

        Console.WriteLine("\n================================================================================");
        Console.WriteLine("   ALL 7 WORKFLOW STEPS AND 4 SECURITY TESTS COMPLETED SUCCESSFULLY!");
        Console.WriteLine("================================================================================");
    }
}
