app.MapPost("/auth/login", (LoginRequest req, ILogger<Program> logger) =>
{
    if (string.IsNullOrWhiteSpace(req.Username) || string.IsNullOrWhiteSpace(req.Password))
        return Results.BadRequest(new { error = "Username and password are required." }); // AC4

    if (!users.TryGetValue(req.Username, out var hashedPassword)
        || !BCrypt.Net.BCrypt.Verify(req.Password, hashedPassword))   // AC5
    {
        logger.LogWarning("Failed login attempt for user '{Username}'", req.Username); // AC6
        return Results.Unauthorized();  // AC3
    }

    // AC2: Issue JWT
    var token = new JwtSecurityToken(issuer, audience, claims,
        expires: DateTime.UtcNow.AddHours(1), signingCredentials: creds);

    return Results.Ok(new { token = tokenString, expiresAt = DateTime.UtcNow.AddHours(1) });
});
