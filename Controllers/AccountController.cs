using Dapper;
using lkjaf.Models;
using lkjaf.Service;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace lkjaf.Controllers
{
    public class AccountController : Controller
    {
        private readonly DapperContext _dapperContext;
        private readonly IJwtService _jwtService;

        public AccountController(DapperContext dapperContext, IJwtService jwtService)
        {
            _dapperContext = dapperContext;
            _jwtService = jwtService;
        }


        [HttpGet]
        [AllowAnonymous]
        public IActionResult Login() => View(); // Show login page

        [HttpPost]
        [AllowAnonymous]
        public async Task<IActionResult> Login(string email, string password)
        {
            using (var con = _dapperContext.CreateConnection()) {

                string query = "Select * from Users where Email = @Email and PasswordHash = @Password";
                var user = await con.QueryFirstOrDefaultAsync<Users>(query, new
                {
                    Email = email,
                    Password = password
                });


                //Cookie Authentication
                //if(user != null)
                //{
                //    var claims = new List<Claim>
                //    {
                //        new Claim(ClaimTypes.Name, user.Email),
                //        new Claim(ClaimTypes.NameIdentifier,user.Id.ToString()),
                //        new Claim(ClaimTypes.Role,"User") // Assign a role
                //    };

                //    var claimsIdentity = new ClaimsIdentity(claims, CookieAuthenticationDefaults.AuthenticationScheme);
                //    var authProperties = new AuthenticationProperties
                //    {
                //        IsPersistent = true
                //    };

                //    await HttpContext.SignInAsync(CookieAuthenticationDefaults.AuthenticationScheme, new ClaimsPrincipal(claimsIdentity), authProperties);

                //    return RedirectToAction("Index", "Home");
                //}

                if (user == null) {
                    ViewBag.Error = "Invalid email or password";
                    return View();
                }

                string token = _jwtService.GenerateToken(user);

                Response.Cookies.Append("AuthToken", token, new CookieOptions
                {
                    HttpOnly = true, // Prevents JavaScript access
                    Secure = true,   // Use Secure cookies in production (HTTPS required)
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTime.UtcNow.AddHours(1)
                });

                return RedirectToAction("Privacy", "Home");
                
            }
        }

        public async Task<IActionResult> LogOut()
        {
            Response.Cookies.Delete("AuthToken"); 
            //await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            return RedirectToAction("Login");
        }

        public IActionResult AccessDenied() => View();
    }
}
