using System.Security.Claims;
using System.Threading.Tasks;

namespace MyProxy
{
    internal class TokenService
    {
        internal Task<string> GetAuthTokenAsync(ClaimsPrincipal user)
        {
            return Task.FromResult(user.Identity.Name);
        }
    }
}