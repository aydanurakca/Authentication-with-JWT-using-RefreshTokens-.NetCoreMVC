using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using JWT_Auth.Models;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.AspNetCore.Identity;
using JWT_Auth.Entities;
using JWT_Auth.Services;
using Microsoft.AspNetCore.Http;

namespace JWT_Auth.Controllers
{
    [Authorize]
    public class HomeController : Controller
    {
        private readonly ILogger<HomeController> _logger;
        private IUserService _userService;
        
        public HomeController(ILogger<HomeController> logger, IUserService userService)
        {
            _logger = logger;
            _userService = userService;
           
        }

        public IActionResult Index()
        {
            LogoutFunction();
            return View("Index");
        }
 
        public IActionResult HomePage()
        {
            if (Request.Cookies["access_token"] != null)
            {
                var token = Request.Cookies["access_token"];
                int? id = _userService.validateJwtToken(token.ToString());

                if (id == null)
                {
                    return RedirectToAction("RefreshToken", "Home", new { returnUrl = "/Home/HomePage" });
                }

                return View();
            }
            return View("Index");
        }
        
        public IActionResult Privacy()
        {
            if (Request.Cookies["access_token"] != null)
            {
                var token = Request.Cookies["access_token"];
                int? id = _userService.validateJwtToken(token.ToString());

                if (id == null)
                {
                    return RedirectToAction("RefreshToken", "Home", new { returnUrl = "/Home/Privacy" });
                }

                return View();
            }
            return View("Index");
        }

        public async Task<IActionResult> LogoutFunction()
        {
            if (Request.Cookies["access_token"] != null)
            {
                Response.Cookies.Delete("access_token");
            }
            if(Request.Cookies["refresh_token"] != null)
            {
                Response.Cookies.Delete("refresh_token");
            }
            return RedirectToAction("Index", "Home");
        }

        public async Task<IActionResult> AuthFunction(AuthenticateRequest model)
        {
            string? token = Authenticate(model);

            if (token == null)
            {
                //Authorization Failed
                return RedirectToAction("Index", "Home");
            }
            else
            {
                setTokenCookie("access_token", token);
                return RedirectToAction("HomePage", "Home");
            }
        }

        public string Authenticate(AuthenticateRequest model)
        {
            AuthenticateResponse response = _userService.Authenticate(model, ipAddress());

            if (response == null)
                return null;

            setTokenCookie("refresh_token", response.RefreshToken);

            return response.JwtToken;
        }

        
        public IActionResult RefreshToken(string returnUrl = "")
        {
            var refreshToken = Request.Cookies["refresh_token"];
            var response = _userService.RefreshToken(refreshToken, ipAddress());

            if (response == null)
                return RedirectToAction("Index", "Home");

            setTokenCookie("refresh_token", response.RefreshToken);
            setTokenCookie("access_token", response.JwtToken);

            if (!String.IsNullOrEmpty(returnUrl) && Url.IsLocalUrl(returnUrl))
                return Redirect(returnUrl);
            else
                return RedirectToAction("HomePage", "Home");
        }

        private void setTokenCookie(string token_name, string token)
        {
            var cookieOptions = new CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                Expires = DateTime.UtcNow.AddDays(1)
            };
            Response.Cookies.Append(token_name, token, cookieOptions);
        }

        private string ipAddress()
        {
            if (Request.Headers.ContainsKey("X-Forwarded-For"))
                return Request.Headers["X-Forwarded-For"];
            else
                return HttpContext.Connection.RemoteIpAddress.MapToIPv4().ToString();
        }
    }
}
