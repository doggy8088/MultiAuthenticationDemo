# MultiAuthenticationDemo

示範在一個 ASP.NET Core 專案中，若要實現多個不同的 `AuthenticationScheme` 要如何實作。

> https://localhost:9001/

## 重要觀念

認證流程主要有五大動作：

1. `Authenticate`

    重點在於如何建立 `IIdentity` (`ClaimsIdentity`) 並提供的框架使用！

    To authenticate basically means to use the given information and attempt to authenticate the user with that information. So this will attempt to **create a user identity** and **make it available for the framework**.

    For example, the cookie authentication scheme uses cookie data to restore the user identity. Or the JWT Bearer authentication scheme will use the token that is provided as part of the Authorization header in the request to create the user identity.

2. `Challenge`

    當用戶端沒有傳來足夠的認證資訊，以致於沒有產生合法的 `IIdentity` 的話，使用者就會遭受到挑戰，而挑戰的方式通常不外乎「導向到登入頁」、「導向到 OIDC 登入頁」、「直接顯示 HTTP 401 Unauthorized 資訊」。

    When an authentication scheme is challenged, the scheme should prompt the user to authenticate themselves. This could for example mean that the user gets redirected to a login form, or that there will be a redirect to an external authentication provider.

3. `Forbid`

    當用戶端已經通過驗證，但沒有足夠的授權資訊，此時可以交由 AuthenticationScheme 負責處理，處理方式通常不外乎「導向到權限不足的說明頁面」、「直接顯示 HTTP 403 Forbidden 資訊」。

    When an authentication scheme is forbidden, the scheme basically just responds with something that tells the user that they may not do whatever they attempted to do. This is commonly a HTTP 403 error, and may be a redirect to some error page.

4. `Sign-in`

    當用戶端遭受到挑戰，而且準備完成「登入」程序時，這個動作可以明確指出使用者該如何完成登入。若是用 Cookies 認證，就會產生一個 Cookie 給用戶端儲存起來。

    When an authentication scheme is being signed in, then the scheme is being told to take an existing user (a ClaimsPrincipal) and to persist that in some way. For example, signing a user in on the cookie authentication scheme will basically create a cookie containing that user’s identity.

5. `Sign-out`

    當用戶端想要「登出」時，這個動作可以幫助使用者完成登出程序。若是用 Cookies 認證，就會幫客戶把相關 Cookie 刪除。

    This is the inverse of sign-in and will basically tell the authentication scheme to remove that persistance. Signing out on the cookie scheme will effectively expire the cookie.

    [Cannot redirect to the end session endpoint, the configuration may be missing or invalid OpenIdConnect SignOutAsync](https://stackoverflow.com/a/51986347/910074)

## 三種不同的 AuthenticationScheme

此專案有同時設定三種 `AuthenticationScheme`：

1. CookieAuthenticationDefaults.AuthenticationScheme (`Cookies`)

    `DefaultScheme` 是預設的 fallback scheme，所以等同於以下都是用 `Cookies` 作為預設的認證方式。因此 `DefaultAuthenticateScheme`, `DefaultForbidScheme`, `DefaultSignInScheme`, `DefaultSignOutScheme` 都是以 Cookies 為主。

    加入 `.AddCookie()` 就是宣告與定義 `Authenticate` 時要執行哪些動作，這裡預設會從使用者傳來的 Cookies 取得認證資訊。

    ```cs
    builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme);
    ```

2. OpenIdConnectDefaults.AuthenticationScheme (`OpenIdConnect`)

    `DefaultChallengeScheme` 是當使用者被「挑戰」的時候，才會用這個進行身份驗證。

    這裡的 `.AddCookie()` 主要用來儲存使用者認證之後會拿到的 Token，而加入 `.AddOpenIdConnect()` 主要只用在 `Challenge` 的時候，這裡定義了要完整「挑戰」時必要的設定。

    ```cs
    builder.Services.AddAuthentication(options =>
        {
            options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
        })
        .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
        {
            options.Authority = "https://accounts.google.com";

            options.ClientId = builder.Configuration["GoogleOAuth:client_id"];
            options.ClientSecret = builder.Configuration["GoogleOAuth:client_secret"];
            options.ResponseType = "code id_token";

            options.Scope.Add("openid");
            options.Scope.Add("profile");
            options.Scope.Add("email");

            // 拿到 Token 之後可以存入 Cookies 保存
            options.SaveTokens = true;
        });
    ```

3. JwtBearerDefaults.AuthenticationScheme (`Bearer`)

    若不用預設值，意味著每個 Controller / Action 都需要特別指定才行。

    ```cs
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public IActionResult GetClaimsFromJwtBearer() {...}
    ```

    加入 `.AddJwtBearer()` 就是宣告與定義 `Authenticate` 時要執行哪些動作，取得 JWT Bearer 取得認證資訊預設就是從 HTTP Request 的 `Authorization: Bearer <TOKEN>` 來取得完整資訊。以下則是驗證 Token 的相關定義：

    ```cs
    builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            // 當驗證失敗時，回應標頭會包含 WWW-Authenticate 標頭，這裡會顯示失敗的詳細錯誤原因
            options.IncludeErrorDetails = true; // 預設值為 true，有時會特別關閉

            options.TokenValidationParameters = new TokenValidationParameters
            {
                // 透過這項宣告，就可以從 "sub" 取值並設定給 User.Identity.Name
                NameClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
                // 透過這項宣告，就可以從 "roles" 取值，並可讓 [Authorize] 判斷角色
                RoleClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",

                // 一般我們都會驗證 Issuer
                ValidateIssuer = true,
                ValidIssuer = builder.Configuration.GetValue<string>("JwtSettings:Issuer"),

                // 通常不太需要驗證 Audience
                ValidateAudience = false,
                //ValidAudience = "JwtAuthDemo", // 不驗證就不需要填寫

                // 一般我們都會驗證 Token 的有效期間
                ValidateLifetime = true,

                // 如果 Token 中包含 key 才需要驗證，一般都只有簽章而已
                ValidateIssuerSigningKey = false,

                // "1234567890123456" 應該從 IConfiguration 取得
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration.GetValue<string>("JwtSettings:SignKey")))
            };
        });
    ```

## 相關連結

- [Authentication: 官方原始碼中完整的實作](https://github.com/dotnet/aspnetcore/tree/v6.0.3/src/Security/Authentication)
- [ASP.NET Core security topics | Microsoft Docs](https://docs.microsoft.com/en-us/aspnet/core/security/?view=aspnetcore-3.1&WT.mc_id=DT-MVP-4015686)
- [**Overview of ASP.NET Core Authentication** | Microsoft Docs](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/?view=aspnetcore-3.1&WT.mc_id=DT-MVP-4015686)
- [IAuthenticationService 介面 (Microsoft.AspNetCore.Authentication) | Microsoft Docs](https://docs.microsoft.com/zh-tw/dotnet/api/microsoft.aspnetcore.authentication.iauthenticationservice?view=aspnetcore-3.1&WT.mc_id=DT-MVP-4015686)
- [ClaimsPrincipal 類別 (System.Security.Claims) | Microsoft Docs](https://docs.microsoft.com/zh-tw/dotnet/api/system.security.claims.claimsprincipal?view=net-6.0&WT.mc_id=DT-MVP-4015686)
- [c# - What is the point of configuring DefaultScheme and DefaultChallengeScheme on ASP.NET Core? - Stack Overflow](https://stackoverflow.com/a/52493428/910074)
- [AuthenticationHttpContextExtensions Class (Microsoft.AspNetCore.Authentication) | Microsoft Docs](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationhttpcontextextensions?view=aspnetcore-2.0&WT.mc_id=DT-MVP-4015686)
- [Identity Server and Auth0 | Bryce’s Blog](https://brycewalther.com/asp.net/2018/05/28/identity-server-and-auth0.html)
