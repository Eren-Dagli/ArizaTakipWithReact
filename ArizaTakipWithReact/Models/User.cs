namespace ArizaTakipWithReact.Models
{
    public class User
    {
        public int UserId { get; set; }
        public string Email { get; set; }
        public string PasswordHash { get; set; }
        public string PasswordSalt { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Department { get; set; }
        public string UserRole { get; set; } = "Student";
        public bool IsActive { get; set; } = true;
        public DateTime CreatedAt { get; set; } = DateTime.Now;
        public DateTime? LastLogin { get; set; }
    }

    // Login isteği için DTO (Data Transfer Object)
    public class LoginRequest
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }

    // Login yanıtı için DTO
    public class LoginResponse
    {
        public bool Success { get; set; }
        public string Message { get; set; }
        public string Token { get; set; }
        public string RefreshToken { get; set; }
        public UserDto User { get; set; }
    }

    // Token Refresh DTO
    public class RefreshTokenRequest
    {
        public string RefreshToken { get; set; }
    }

    // Kullanıcı Bilgileri DTO (hassas veriler olmadan)
    public class UserDto
    {
        public int UserId { get; set; }
        public string Email { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Department { get; set; }
        public string UserRole { get; set; }
    }

}
