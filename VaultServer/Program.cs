using System.Text.Json;
using VaultServer.Data;
using VaultServer.Services;
using VaultShared.Protocol;

var builder = WebApplication.CreateBuilder(args);

// Add services to DI container
builder.Services.AddSingleton<VaultDbContext>();
builder.Services.AddScoped<AccountService>();
builder.Services.AddScoped<VaultStoreService>();
builder.Services.AddScoped<AuthValidator>();

var app = builder.Build();

// Ensure SQLite schema is created on startup
var dbContext = app.Services.GetRequiredService<VaultDbContext>();
dbContext.InitializeDatabase();

// -----------------------------------------------------------------------------------------
// 1. POST /register
// Unsigned endpoint to register email and public key. Account starts in unverified state.
// -----------------------------------------------------------------------------------------
app.MapPost("/register", async (RegisterRequest request, AccountService accountService) =>
{
    var (success, errorCode, errorMessage, token) = await accountService.RegisterAsync(request);
    if (!success)
    {
        int statusCode = errorCode == "email_already_registered" ? StatusCodes.Status409Conflict : StatusCodes.Status400BadRequest;
        return Results.Json(new ApiErrorResponse { Error = errorCode!, Message = errorMessage! }, statusCode: statusCode);
    }

    return Results.Json(new RegisterResponse
    {
        Email = request.Email.Trim().ToLowerInvariant(),
        VerificationToken = token!
    }, statusCode: StatusCodes.Status201Created);
});

// -----------------------------------------------------------------------------------------
// 2. POST /verify
// Signed envelope containing VerifyPayload { type: "verify", token: "..." }.
// requireVerified = false (because this step establishes verification).
// -----------------------------------------------------------------------------------------
app.MapPost("/verify", async (
    RequestEnvelope envelope,
    AuthValidator validator,
    AccountService accountService) =>
{
    var authResult = await validator.ValidateRequestAsync(envelope, requireVerified: false);
    if (!authResult.IsValid)
    {
        return Results.Json(new ApiErrorResponse { Error = authResult.ErrorCode!, Message = authResult.Message! }, statusCode: authResult.StatusCode);
    }

    VerifyPayload? payload;
    try
    {
        payload = JsonSerializer.Deserialize<VerifyPayload>(authResult.RawPayloadBytes!, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
    }
    catch
    {
        return Results.Json(new ApiErrorResponse { Error = "malformed_request", Message = "Invalid JSON in verify payload." }, statusCode: StatusCodes.Status400BadRequest);
    }

    if (payload == null || payload.Type != "verify" || string.IsNullOrWhiteSpace(payload.Token))
    {
        return Results.Json(new ApiErrorResponse { Error = "payload_type_mismatch", Message = "Payload must be type 'verify' with a valid token." }, statusCode: StatusCodes.Status400BadRequest);
    }

    var (success, errorCode, errorMessage) = await accountService.VerifyAccountAsync(envelope.Email, payload.Token, envelope.Nonce);
    if (!success)
    {
        int status = errorCode switch
        {
            "account_not_found" => StatusCodes.Status404NotFound,
            "token_already_used" => StatusCodes.Status410Gone,
            "invalid_token" => StatusCodes.Status400BadRequest,
            _ => StatusCodes.Status400BadRequest
        };
        return Results.Json(new ApiErrorResponse { Error = errorCode!, Message = errorMessage! }, statusCode: status);
    }

    return Results.Json(new { verified = true, email = envelope.Email, verifiedAt = DateTimeOffset.UtcNow.ToString("O") });
});

// -----------------------------------------------------------------------------------------
// 3. POST /store
// Signed envelope containing StorePayload { type: "store", vault: "<base64>" }.
// requireVerified = true.
// -----------------------------------------------------------------------------------------
app.MapPost("/store", async (
    RequestEnvelope envelope,
    AuthValidator validator,
    VaultStoreService vaultStoreService) =>
{
    var authResult = await validator.ValidateRequestAsync(envelope, requireVerified: true);
    if (!authResult.IsValid)
    {
        return Results.Json(new ApiErrorResponse { Error = authResult.ErrorCode!, Message = authResult.Message! }, statusCode: authResult.StatusCode);
    }

    StorePayload? payload;
    try
    {
        payload = JsonSerializer.Deserialize<StorePayload>(authResult.RawPayloadBytes!, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
    }
    catch
    {
        return Results.Json(new ApiErrorResponse { Error = "malformed_request", Message = "Invalid JSON in store payload." }, statusCode: StatusCodes.Status400BadRequest);
    }

    if (payload == null || payload.Type != "store" || string.IsNullOrWhiteSpace(payload.Vault))
    {
        return Results.Json(new ApiErrorResponse { Error = "payload_type_mismatch", Message = "Payload must be type 'store' containing the 'vault' ciphertext." }, statusCode: StatusCodes.Status400BadRequest);
    }

    var (success, errorCode, errorMessage, storedAt) = await vaultStoreService.StoreVaultAsync(envelope.Email, payload.Vault, envelope.Nonce);
    if (!success)
    {
        return Results.Json(new ApiErrorResponse { Error = errorCode!, Message = errorMessage! }, statusCode: StatusCodes.Status400BadRequest);
    }

    return Results.Json(new { storedAt, email = envelope.Email, status = "stored" });
});

// -----------------------------------------------------------------------------------------
// 4. POST /retrieve
// Signed envelope containing RetrievePayload { type: "retrieve" }.
// requireVerified = true.
// -----------------------------------------------------------------------------------------
app.MapPost("/retrieve", async (
    RequestEnvelope envelope,
    AuthValidator validator,
    VaultStoreService vaultStoreService) =>
{
    var authResult = await validator.ValidateRequestAsync(envelope, requireVerified: true);
    if (!authResult.IsValid)
    {
        return Results.Json(new ApiErrorResponse { Error = authResult.ErrorCode!, Message = authResult.Message! }, statusCode: authResult.StatusCode);
    }

    RetrievePayload? payload;
    try
    {
        payload = JsonSerializer.Deserialize<RetrievePayload>(authResult.RawPayloadBytes!, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
    }
    catch
    {
        return Results.Json(new ApiErrorResponse { Error = "malformed_request", Message = "Invalid JSON in retrieve payload." }, statusCode: StatusCodes.Status400BadRequest);
    }

    if (payload == null || payload.Type != "retrieve")
    {
        return Results.Json(new ApiErrorResponse { Error = "payload_type_mismatch", Message = "Payload must be type 'retrieve'." }, statusCode: StatusCodes.Status400BadRequest);
    }

    var (success, errorCode, errorMessage, result) = await vaultStoreService.RetrieveVaultAsync(envelope.Email, envelope.Nonce);
    if (!success)
    {
        int status = errorCode == "vault_not_found" ? StatusCodes.Status404NotFound : StatusCodes.Status400BadRequest;
        return Results.Json(new ApiErrorResponse { Error = errorCode!, Message = errorMessage! }, statusCode: status);
    }

    return Results.Json(result);
});

// Health check endpoint
app.MapGet("/health", () => Results.Ok(new { status = "healthy", service = "VaultBackup.Server", version = "1.0.0" }));

app.Run();
