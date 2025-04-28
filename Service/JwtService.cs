using lkjaf.Models;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace lkjaf.Service
{
    public class JwtService : IJwtService
    {
        private readonly string _secretKey;
        private readonly IConfiguration config;

        public JwtService(IConfiguration configuration)
        {
            _secretKey = configuration["Jwt:SecretKey"];
            config = configuration;
        }

     

        public string GenerateToken(Users user)
        {
            var claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Email),
                new Claim(ClaimTypes.Role,user.Roles),
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, user.Id.ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_secretKey));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: config["Jwt:Issuer"],  // You can change this to your own issuer
                audience: config["Jwt:Audience"],  // You can change this to your own audience
                claims: claims,
                expires: DateTime.Now.AddMinutes(30), // You can set the expiration time
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        public bool ValidateToken(string token)
        {
            var key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_secretKey));

            var tokenHandler = new JwtSecurityTokenHandler();
            try
            {
                tokenHandler.ValidateToken(token, new TokenValidationParameters
                {
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = true,
                    IssuerSigningKey = key,
                    ClockSkew = TimeSpan.Zero,
                    ValidIssuer = config["Jwt:Issuer"],  // Match with the issuer used in token generation
                    ValidAudience = config["Jwt:Audience"]  // Match with the audience used in token generation
                }, out var validatedToken);

                return true;
            }
            catch
            {
                return false;
            }
        }
    }
}
