using lkjaf.Models;

namespace lkjaf.Service
{
    public interface IJwtService
    {
        string GenerateToken(Users user);
        bool ValidateToken(string token);
    }
}
