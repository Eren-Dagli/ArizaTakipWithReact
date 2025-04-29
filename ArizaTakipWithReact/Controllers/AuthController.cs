using ArizaTakipWithReact.Models;
using ArizaTakipWithReact.Services;
using Microsoft.AspNetCore.Mvc;

namespace ArizaTakipWithReact.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthService _authService;

        public AuthController(IAuthService authService)
        {
            _authService = authService;
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            // İstemci IP adresi ve kullanıcı ajanını al
            var ipAddress = HttpContext.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var userAgent = Request.Headers["User-Agent"].ToString();

            var result = await _authService.Login(request, ipAddress, userAgent);

            if (!result.Success)
                return BadRequest(result);

            return Ok(result);
        }
    }
}

