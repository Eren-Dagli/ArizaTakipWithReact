using ArizaTakipWithReact.Data;
using ArizaTakipWithReact.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace ArizaTakipWithReact.Services
{
    public class AuthService : IAuthService
    {
        private readonly AppDbContext _context;
        private readonly IConfiguration _configuration;

        public AuthService(AppDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        public async Task<LoginResponse> Login(LoginRequest request, string ipAddress, string userAgent)
        {
            // E-posta kontrol
            if (!IsValidEmail(request.Email))
            {
                await LogLoginAttempt(request.Email, "Failed", ipAddress, userAgent);
                return new LoginResponse { Success = false, Message = "Geçersiz e-posta formatı. Öğrenci girişi için @ogr.akdeniz.edu.tr uzantılı adres kullanınız." };
            }

            // Kullanıcıyı veritabanında ara
            var user = await _context.Users
                .FirstOrDefaultAsync(u => u.Email.ToLower() == request.Email.ToLower() && u.IsActive);

            if (user == null)
            {
                await LogLoginAttempt(request.Email, "Failed", ipAddress, userAgent);
                return new LoginResponse { Success = false, Message = "Geçersiz kullanıcı adı veya şifre." };
            }

            // Şifre kontrolü
            if (!VerifyPasswordHash(request.Password, user.PasswordHash, user.PasswordSalt))
            {
                await LogLoginAttempt(request.Email, "Failed", ipAddress, userAgent);
                return new LoginResponse { Success = false, Message = "Geçersiz kullanıcı adı veya şifre." };
            }

            // JWT ve Refresh Token oluştur
            var token = GenerateJwtToken(user);
            var refreshToken = GenerateRefreshToken();

            // Refresh token'ı kaydet
            var userToken = new UserToken
            {
                UserId = user.UserId,
                RefreshToken = refreshToken,
                RefreshTokenExpiry = DateTime.Now.AddDays(7) // 7 gün geçerli
            };

            _context.UserTokens.Add(userToken);

            // Son giriş zamanını güncelle
            user.LastLogin = DateTime.Now;
            _context.Users.Update(user);

            await _context.SaveChangesAsync();
            await LogLoginAttempt(request.Email, "Success", ipAddress, userAgent);

            return new LoginResponse
            {
                Success = true,
                Message = "Giriş başarılı",
                Token = token,
                RefreshToken = refreshToken,
                User = new UserDto
                {
                    UserId = user.UserId,
                    Email = user.Email,
                    FirstName = user.FirstName,
                    LastName = user.LastName,
                    Department = user.Department,
                    UserRole = user.UserRole
                }
            };
        }

        private bool IsValidEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email))
                return false;

            try
            {
                // Öğrenci maili kontrolü
                if (email.EndsWith("@ogr.akdeniz.edu.tr", StringComparison.OrdinalIgnoreCase) ||
                    email.EndsWith("@akdeniz.edu.tr", StringComparison.OrdinalIgnoreCase))
                {
                    // Ek email formatı kontrolü yapılabilir
                    return true;
                }
                return false;
            }
            catch
            {
                return false;
            }
        }

        private async Task LogLoginAttempt(string email, string status, string ipAddress, string userAgent)
        {
            var loginLog = new LoginLog
            {
                Email = email,
                Status = status,
                IPAddress = ipAddress,
                UserAgent = userAgent
            };

            _context.LoginLogs.Add(loginLog);
            await _context.SaveChangesAsync();
        }

        private bool VerifyPasswordHash(string password, string storedHash, string storedSalt)
        {
            using (var hmac = new HMACSHA512(HexToByteArray(storedSalt)))
            {
                var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
                var computedHashString = BitConverter.ToString(computedHash).Replace("-", "");
                return computedHashString.Equals(storedHash, StringComparison.OrdinalIgnoreCase);
            }
        }

        private byte[] HexToByteArray(string hex)
        {
            int NumberChars = hex.Length;
            byte[] bytes = new byte[NumberChars / 2];
            for (int i = 0; i < NumberChars; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        private string GenerateJwtToken(User user)
        {
            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Secret"]);
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, user.UserId.ToString()),
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim(ClaimTypes.Role, user.UserRole)
                }),
                Expires = DateTime.UtcNow.AddHours(1), // 1 saat geçerli
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Issuer = _configuration["Jwt:Issuer"],
                Audience = _configuration["Jwt:Audience"]
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }
    }

    public interface IAuthService
    {
        Task<LoginResponse> Login(LoginRequest request, string ipAddress, string userAgent);
    }
}
