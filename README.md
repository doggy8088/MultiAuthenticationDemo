# MultiAuthenticationDemo

�ܽd�b�@�� ASP.NET Core �M�פ��A�Y�n��{�h�Ӥ��P�� `AuthenticationScheme` �n�p���@�C

> https://localhost:9001/

## ���n�[��

�{�Ҭy�{�D�n�����j�ʧ@�G

1. `Authenticate`

    ���I�b��p��إ� `IIdentity` (`ClaimsIdentity`) �ô��Ѫ��ج[�ϥΡI

    To authenticate basically means to use the given information and attempt to authenticate the user with that information. So this will attempt to **create a user identity** and **make it available for the framework**.

    For example, the cookie authentication scheme uses cookie data to restore the user identity. Or the JWT Bearer authentication scheme will use the token that is provided as part of the Authorization header in the request to create the user identity.

2. `Challenge`

    ��Τ�ݨS���ǨӨ������{�Ҹ�T�A�H�P��S�����ͦX�k�� `IIdentity` ���ܡA�ϥΪ̴N�|�D����D�ԡA�ӬD�Ԫ��覡�q�`���~�G�u�ɦV��n�J���v�B�u�ɦV�� OIDC �n�J���v�B�u������� HTTP 401 Unauthorized ��T�v�C

    When an authentication scheme is challenged, the scheme should prompt the user to authenticate themselves. This could for example mean that the user gets redirected to a login form, or that there will be a redirect to an external authentication provider.

3. `Forbid`

    ��Τ�ݤw�g�q�L���ҡA���S�����������v��T�A���ɥi�H��� AuthenticationScheme �t�d�B�z�A�B�z�覡�q�`���~�G�u�ɦV���v�����������������v�B�u������� HTTP 403 Forbidden ��T�v�C

    When an authentication scheme is forbidden, the scheme basically just responds with something that tells the user that they may not do whatever they attempted to do. This is commonly a HTTP 403 error, and may be a redirect to some error page.

4. `Sign-in`

    ��Τ�ݾD����D�ԡA�ӥB�ǳƧ����u�n�J�v�{�ǮɡA�o�Ӱʧ@�i�H���T���X�ϥΪ̸Ӧp�󧹦��n�J�C�Y�O�� Cookies �{�ҡA�N�|���ͤ@�� Cookie ���Τ���x�s�_�ӡC

    When an authentication scheme is being signed in, then the scheme is being told to take an existing user (a ClaimsPrincipal) and to persist that in some way. For example, signing a user in on the cookie authentication scheme will basically create a cookie containing that user��s identity.

5. `Sign-out`

    ��Τ�ݷQ�n�u�n�X�v�ɡA�o�Ӱʧ@�i�H���U�ϥΪ̧����n�X�{�ǡC�Y�O�� Cookies �{�ҡA�N�|���Ȥ����� Cookie �R���C

    This is the inverse of sign-in and will basically tell the authentication scheme to remove that persistance. Signing out on the cookie scheme will effectively expire the cookie.

    [Cannot redirect to the end session endpoint, the configuration may be missing or invalid OpenIdConnect SignOutAsync](https://stackoverflow.com/a/51986347/910074)

## �T�ؤ��P�� AuthenticationScheme

���M�צ��P�ɳ]�w�T�� `AuthenticationScheme`�G

1. CookieAuthenticationDefaults.AuthenticationScheme (`Cookies`)

    `DefaultScheme` �O�w�]�� fallback scheme�A�ҥH���P��H�U���O�� `Cookies` �@���w�]���{�Ҥ覡�C�]�� `DefaultAuthenticateScheme`, `DefaultForbidScheme`, `DefaultSignInScheme`, `DefaultSignOutScheme` ���O�H Cookies ���D�C

    �[�J `.AddCookie()` �N�O�ŧi�P�w�q `Authenticate` �ɭn������ǰʧ@�A�o�̹w�]�|�q�ϥΪ̶ǨӪ� Cookies ���o�{�Ҹ�T�C

    ```cs
    builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
        .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme);
    ```

2. OpenIdConnectDefaults.AuthenticationScheme (`OpenIdConnect`)

    `DefaultChallengeScheme` �O��ϥΪ̳Q�u�D�ԡv���ɭԡA�~�|�γo�Ӷi�樭�����ҡC

    �o�̪� `.AddCookie()` �D�n�Ψ��x�s�ϥΪ̻{�Ҥ���|���쪺 Token�A�ӥ[�J `.AddOpenIdConnect()` �D�n�u�Φb `Challenge` ���ɭԡA�o�̩w�q�F�n����u�D�ԡv�ɥ��n���]�w�C

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

            // ���� Token ����i�H�s�J Cookies �O�s
            options.SaveTokens = true;
        });
    ```

3. JwtBearerDefaults.AuthenticationScheme (`Bearer`)

    �Y���ιw�]�ȡA�N���ۨC�� Controller / Action ���ݭn�S�O���w�~��C

    ```cs
    [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
    public IActionResult GetClaimsFromJwtBearer() {...}
    ```

    �[�J `.AddJwtBearer()` �N�O�ŧi�P�w�q `Authenticate` �ɭn������ǰʧ@�A���o JWT Bearer ���o�{�Ҹ�T�w�]�N�O�q HTTP Request �� `Authorization: Bearer <TOKEN>` �Ө��o�����T�C�H�U�h�O���� Token �������w�q�G

    ```cs
    builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            // �����ҥ��ѮɡA�^�����Y�|�]�t WWW-Authenticate ���Y�A�o�̷|��ܥ��Ѫ��Բӿ��~��]
            options.IncludeErrorDetails = true; // �w�]�Ȭ� true�A���ɷ|�S�O����

            options.TokenValidationParameters = new TokenValidationParameters
            {
                // �z�L�o���ŧi�A�N�i�H�q "sub" ���Ȩó]�w�� User.Identity.Name
                NameClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier",
                // �z�L�o���ŧi�A�N�i�H�q "roles" ���ȡA�åi�� [Authorize] �P�_����
                RoleClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role",

                // �@��ڭ̳��|���� Issuer
                ValidateIssuer = true,
                ValidIssuer = builder.Configuration.GetValue<string>("JwtSettings:Issuer"),

                // �q�`���ӻݭn���� Audience
                ValidateAudience = false,
                //ValidAudience = "JwtAuthDemo", // �����ҴN���ݭn��g

                // �@��ڭ̳��|���� Token �����Ĵ���
                ValidateLifetime = true,

                // �p�G Token ���]�t key �~�ݭn���ҡA�@�볣�u��ñ���Ӥw
                ValidateIssuerSigningKey = false,

                // "1234567890123456" ���ӱq IConfiguration ���o
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration.GetValue<string>("JwtSettings:SignKey")))
            };
        });
    ```

## �����s��

- [Authentication: �x���l�X�����㪺��@](https://github.com/dotnet/aspnetcore/tree/v6.0.3/src/Security/Authentication)
- [ASP.NET Core security topics | Microsoft Docs](https://docs.microsoft.com/en-us/aspnet/core/security/?view=aspnetcore-3.1&WT.mc_id=DT-MVP-4015686)
- [**Overview of ASP.NET Core Authentication** | Microsoft Docs](https://docs.microsoft.com/en-us/aspnet/core/security/authentication/?view=aspnetcore-3.1&WT.mc_id=DT-MVP-4015686)
- [IAuthenticationService ���� (Microsoft.AspNetCore.Authentication) | Microsoft Docs](https://docs.microsoft.com/zh-tw/dotnet/api/microsoft.aspnetcore.authentication.iauthenticationservice?view=aspnetcore-3.1&WT.mc_id=DT-MVP-4015686)
- [ClaimsPrincipal ���O (System.Security.Claims) | Microsoft Docs](https://docs.microsoft.com/zh-tw/dotnet/api/system.security.claims.claimsprincipal?view=net-6.0&WT.mc_id=DT-MVP-4015686)
- [c# - What is the point of configuring DefaultScheme and DefaultChallengeScheme on ASP.NET Core? - Stack Overflow](https://stackoverflow.com/a/52493428/910074)
- [AuthenticationHttpContextExtensions Class (Microsoft.AspNetCore.Authentication) | Microsoft Docs](https://docs.microsoft.com/en-us/dotnet/api/microsoft.aspnetcore.authentication.authenticationhttpcontextextensions?view=aspnetcore-2.0&WT.mc_id=DT-MVP-4015686)
- [Identity Server and Auth0 | Bryce��s Blog](https://brycewalther.com/asp.net/2018/05/28/identity-server-and-auth0.html)
