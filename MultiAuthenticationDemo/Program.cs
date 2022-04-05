using System.Text;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();

builder.Services.AddSingleton<JwtHelpers>();

builder.Services.AddAuthentication(options =>
    {
        options.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
        options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
        options.DefaultSignOutScheme = OpenIdConnectDefaults.AuthenticationScheme;

    })
    .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme)
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
    })
    .AddOpenIdConnect(OpenIdConnectDefaults.AuthenticationScheme, options =>
    {
        options.Authority = "https://accounts.google.com";

        options.ClientId = builder.Configuration["GoogleOAuth:client_id"];
        options.ClientSecret = builder.Configuration["GoogleOAuth:client_secret"];
        options.ResponseType = "code id_token";

        options.Scope.Add("openid");
        options.Scope.Add("profile");
        options.Scope.Add("email");

        options.Events = new OpenIdConnectEvents()
        {
            // �i�H�Φb OAuth 2.0 �b�@�}�l�i�J Authorization Endpoint ���ɭԡA�i�H��J�@���B�~�� Query String �ѼơA�νվ�ۭq�� state ���e
            //OnRedirectToIdentityProvider = context =>
            //{
            //    context.ProtocolMessage.SetParameter("pfidpadapterid", builder.Configuration["oidc:PingProtocolMessage"] ?? "OK");
            //    //context.ProtocolMessage.State = "111";
            //    return Task.FromResult(0);
            //},

            // �Y IdP �L�k�i�� Remote Signout ���ܡA�i�H�ۦ���w�@�ӥi�H���ݵn�X����}
            OnRedirectToIdentityProviderForSignOut = context =>
            {
                context.ProtocolMessage.IssuerAddress = "https://blog.miniasp.com/";

                /*
                 * https://blog.miniasp.com/?
                 *     post_logout_redirect_uri=https%3A%2F%2Flocalhost%3A9001%2Fsignout-callback-oidc&
                 *     id_token_hint=eyJhbGciOiJSUzI1NiIsImtpZCI6ImNlYzEzZGViZjRiOTY0Nzk2ODM3MzYyMDUwODI0NjZjMTQ3OTdiZDAiLCJ0eXAiOiJKV1QifQ.eyJpc3MiOiJodHRwczovL2FjY291bnRzLmdvb2dsZS5jb20iLCJhenAiOiIyOTgxNjMxMzY4NzQtcjlldTQ4ZmUwaTdhdm9nN2lqcmlmMXMwN3VmaXNnbHEuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJhdWQiOiIyOTgxNjMxMzY4NzQtcjlldTQ4ZmUwaTdhdm9nN2lqcmlmMXMwN3VmaXNnbHEuYXBwcy5nb29nbGV1c2VyY29udGVudC5jb20iLCJzdWIiOiIxMDMwOTc2ODMzOTQ2NDkwNTgzMTIiLCJlbWFpbCI6ImRvZ2d5Lmh1YW5nQGdtYWlsLmNvbSIsImVtYWlsX3ZlcmlmaWVkIjp0cnVlLCJhdF9oYXNoIjoiQ1VKYmIyazZfaUhKVzlPNG02cXRPdyIsIm5vbmNlIjoiNjM3ODQ3NzA2NDQxOTk2MzQyLk5tVXlNVFF3WmpNdE5EaGpNeTAwT1RSaExUaG1PVE10TURGak1qTTJNak5rTmpBMVkyTXlZemM0TlRVdFpUVXhOQzAwWTJRM0xXSm1OMkV0WldOa05qZzROV0ZpWWpBdyIsIm5hbWUiOiJXaWxs5L-d5ZOlIiwicGljdHVyZSI6Imh0dHBzOi8vbGgzLmdvb2dsZXVzZXJjb250ZW50LmNvbS9hLS9BT2gxNEdoam9fMWRxaERIa1BmLU80bUhGbnlEa3BDWlBaZUkxaUtVSDJ6V0lRPXM5Ni1jIiwiZ2l2ZW5fbmFtZSI6IuS_neWTpSIsImZhbWlseV9uYW1lIjoiV2lsbCIsImxvY2FsZSI6InpoLVRXIiwiaWF0IjoxNjQ5MTczODQ1LCJleHAiOjE2NDkxNzc0NDV9.ZIvkfR7ci-EJ863bdxauLYHCa7U3GdUIK93JkPTW_8ZT79WcSKGKI7EA-GUxKVsP_13N1maX8NswgICpYl59L-Y7LmknT0Vs214HO4S2bnLaZOSCqNSXZ5IGCEcAYXUr74_5Df4UmQyx_awLgMhqVqj0_m5OfSWVpc5qvtX0Yz8FlOhHsvD1JMDeCQHTx8xKf_06KD4GgOK68f8pJ8qQAVONpaNhJb5ODIC44GIqA5ecktNFRDt_5SV13aoGUWhFPMBBhsOI5rB1Uw2Yz4qx59HM9pjRdJ30EinwkmFyFS8lg7v3FiT12BeYYvzdqvixl1JjiR7_LKhDsQd-Aoa67g&
                 *     state=CfDJ8Kgt4DkEyllJjSdRs8bBonJnhuSrVk273ooZx2e1XUZzT2fGP1HaLVl8nODk8oqjtyEO9fmOS24Rq9wM_1sVmtvD84lZsqoa2FmRNZ3iSTynTHutdhvYA1royPCualrCCGACFx-lmfIH_WkjruN3JpE&
                 *     x-client-SKU=ID_NETSTANDARD2_0&
                 *     x-client-ver=6.10.0.0
                 */

                return Task.CompletedTask;
            }
        };

        // ���� Token ����i�H�s�J Cookies �O�s
        options.SaveTokens = true;
    });

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
