using lkjaf.Service;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace lkjaf
{
    public class JwtAuthorizeFilter :IAuthorizationFilter
    {
        private readonly IJwtService _jwtService;

        public JwtAuthorizeFilter(IJwtService jwtService)
        {
            _jwtService = jwtService;
        }

        public void OnAuthorization(AuthorizationFilterContext context)
        {
            var token = context.HttpContext.Request.Cookies["AuthToken"];

            if (string.IsNullOrEmpty(token) || !_jwtService.ValidateToken(token))
            {
                context.Result = new RedirectToActionResult("Login","Account",null); // Return Unauthorized if the token is invalid
                
            }
        }
    }
}
