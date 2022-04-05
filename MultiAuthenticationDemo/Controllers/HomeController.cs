using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MultiAuthenticationDemo.Models;
using System.Diagnostics;
using System.Security.Claims;

namespace MultiAuthenticationDemo.Controllers
{
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private readonly JwtHelpers jwt;

        public HomeController(ILogger<HomeController> logger, JwtHelpers jwt)
        {
            _logger = logger;
            this.jwt = jwt;
        }

        public IActionResult Index()
        {
            return View();
        }

        [Authorize(AuthenticationSchemes = OpenIdConnectDefaults.AuthenticationScheme)]
        public IActionResult Privacy()
        {
            return View();
        }

        public IActionResult GenerateToken()
        {
            return Ok(new
            {
                token = jwt.GenerateToken("will")
            });
        }

        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public async Task<IActionResult> GetTokenFromJwtBearerAsync()
        {
            var accessToken = await HttpContext.GetTokenAsync(JwtBearerDefaults.AuthenticationScheme, "access_token");

            return Ok(new
            {
                accessToken
            });
        }

        [Authorize(AuthenticationSchemes = OpenIdConnectDefaults.AuthenticationScheme)]
        public async Task<IActionResult> GetTokenFromOpenIdConnectAsync()
        {
            var accessToken = await HttpContext.GetTokenAsync(OpenIdConnectDefaults.AuthenticationScheme, "access_token");

            return Ok(new
            {
                accessToken
            });
        }

        [Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
        public async Task<IActionResult> GetTokenFromCookieAsync()
        {
            var accessToken = await HttpContext.GetTokenAsync(CookieAuthenticationDefaults.AuthenticationScheme, "access_token");

            return Ok(new
            {
                accessToken
            });
        }

        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public IActionResult GetClaimsFromJwtBearer()
        {
            return Ok(new
            {
                Claims = HttpContext.User.Claims.Select(c => new
                {
                    Type = c.Type,
                    ShortTypeName = c.Properties.ContainsKey("http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/ShortTypeName")
                        ? c.Properties["http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/ShortTypeName"]
                        : "",
                    Value = c.Value,
                    Properties = c.Properties
                }),
                ClaimsDetail = HttpContext.User.Claims.Select(c => new
                {
                    Subject = new
                    {
                        c.Subject?.Name,
                        c.Subject?.NameClaimType,
                        c.Subject?.RoleClaimType,
                        c.Subject?.Label,
                        c.Subject?.Actor,
                        c.Subject?.AuthenticationType,
                        c.Subject?.BootstrapContext,
                    },
                    c.Type,
                    c.ValueType,
                    c.Value,
                    c.Issuer,
                    c.OriginalIssuer,
                    Properties = c.Properties.Select(p => new
                    {
                        p.Key,
                        p.Value
                    })
                })
            });
        }

        [Authorize(AuthenticationSchemes = OpenIdConnectDefaults.AuthenticationScheme)]
        public IActionResult GetClaimsFromOpenIdConnect()
        {
            return Ok(new
            {
                Claims = HttpContext.User.Claims.Select(c => new
                {
                    Type = c.Type,
                    ShortTypeName = c.Properties.ContainsKey("http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/ShortTypeName")
                        ? c.Properties["http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/ShortTypeName"]
                        : "",
                    Value = c.Value,
                    Properties = c.Properties
                }),
                ClaimsDetail = HttpContext.User.Claims.Select(c => new
                {
                    Subject = new
                    {
                        c.Subject?.Name,
                        c.Subject?.NameClaimType,
                        c.Subject?.RoleClaimType,
                        c.Subject?.Label,
                        c.Subject?.Actor,
                        c.Subject?.AuthenticationType,
                        c.Subject?.BootstrapContext,
                    },
                    c.Type,
                    c.ValueType,
                    c.Value,
                    c.Issuer,
                    c.OriginalIssuer,
                    Properties = c.Properties.Select(p => new
                    {
                        p.Key,
                        p.Value
                    })
                })
            });
        }

        [Authorize(AuthenticationSchemes = CookieAuthenticationDefaults.AuthenticationScheme)]
        public IActionResult GetClaimsFromCookie()
        {
            
            return Ok(new
            {
                IdentityAuthenticationType = HttpContext.User.Identity?.AuthenticationType,
                IdentityName = HttpContext.User.Identity?.Name,
                IdentityIsAuthenticated = HttpContext.User.Identity?.IsAuthenticated,
                HasClaimName = HttpContext.User.HasClaim(ClaimTypes.Name, "Will保哥"),
                HasClaimEmailVerified = HttpContext.User.HasClaim("email_verified", "true"),
                Claims = HttpContext.User.Claims.Select(c => new
                {
                    Type = c.Type,
                    ShortTypeName = c.Properties.ContainsKey("http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/ShortTypeName")
                        ? c.Properties["http://schemas.xmlsoap.org/ws/2005/05/identity/claimproperties/ShortTypeName"]
                        : "",
                    Value = c.Value,
                    Properties = c.Properties
                }),
                ClaimsDetail = HttpContext.User.Claims.Select(c => new
                {
                    Subject = new
                    {
                        c.Subject?.Name,
                        c.Subject?.NameClaimType,
                        c.Subject?.RoleClaimType,
                        c.Subject?.Label,
                        c.Subject?.Actor,
                        c.Subject?.AuthenticationType,
                        c.Subject?.BootstrapContext,
                    },
                    c.Type,
                    c.ValueType,
                    c.Value,
                    c.Issuer,
                    c.OriginalIssuer,
                    Properties = c.Properties.Select(p => new
                    {
                        p.Key,
                        p.Value
                    })
                })
            });
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }
    }
}