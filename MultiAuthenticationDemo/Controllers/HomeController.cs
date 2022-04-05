using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using MultiAuthenticationDemo.Models;
using System.Diagnostics;
using System.Net;
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

        public async Task<IActionResult> SignOutCookiesAsync()
        {
            // 預設會清空 Cookie，而且不會自動轉址，單純寫入 Set-Cookie Header 而已
            await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme, new AuthenticationProperties()
            {
                RedirectUri = "/"
            });

            return RedirectToAction("Index");
        }

        public async Task<IActionResult> SignOutOpenIdConnectAsync()
        {
            // 如果 Claims 中缺乏 JwtRegisteredClaimNames.Sid (SessionID) 的話，那就無法實現遠端登出功能。

            // 大部分的 OpenId Connect 提供者都沒有提供「登出」功能！
            await HttpContext.SignOutAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties()
            {
                RedirectUri = "/"
            });

            return StatusCode((int)HttpStatusCode.Redirect);
        }

        public async Task<IActionResult> SignOutJwtBearer()
        {

            // Bearer 沒有在 Logout 的喔，所以不能用這個方法！
            await HttpContext.SignOutAsync(JwtBearerDefaults.AuthenticationScheme, new AuthenticationProperties()
            {
                RedirectUri = "/"
            });

            return StatusCode((int)HttpStatusCode.Redirect);
        }

        public IActionResult SignInJwtBearer()
        {
            return Ok(new
            {
                token = jwt.GenerateToken("will")
            });
        }

        public async Task<IActionResult> SignInOpenIdConnectAsync()
        {
            if (User.Identity!.IsAuthenticated)
            {
                return RedirectToAction(nameof(Privacy));
            }
            else
            {
                // 預設只會單純寫入 Location 到回應標頭中而已，你還要回應 HTTP 302 才會真的轉址！
                await HttpContext.ChallengeAsync(OpenIdConnectDefaults.AuthenticationScheme, new AuthenticationProperties()
                {
                    RedirectUri = "/"
                });

                return StatusCode((int)HttpStatusCode.Redirect);
            }
        }

        public async Task<IActionResult> SignInCookies()
        {
            if (User.Identity!.IsAuthenticated)
            {
                return RedirectToAction(nameof(Privacy));
            }
            else
            {
                await HttpContext.ChallengeAsync(CookieAuthenticationDefaults.AuthenticationScheme, new AuthenticationProperties()
                {
                    RedirectUri = "/"
                });
                return StatusCode((int)HttpStatusCode.Redirect);
            }
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