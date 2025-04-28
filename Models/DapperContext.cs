using Microsoft.Data.SqlClient;
using System.Data;

namespace lkjaf.Models
{
    public class DapperContext
    {
        private readonly string? _connectionstring = string.Empty;
        public DapperContext(IConfiguration configuration)
        {
            _connectionstring = configuration.GetConnectionString("DefaultConnection");
        }

        public IDbConnection CreateConnection()
            => new SqlConnection(_connectionstring);
    }
}
