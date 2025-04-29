using ArizaTakipWithReact.Models;
using Microsoft.EntityFrameworkCore;
using System.Collections.Generic;
using System.Reflection.Emit;

namespace ArizaTakipWithReact.Data
{
    public class AppDbContext : DbContext
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }

        public DbSet<User> Users { get; set; }
        public DbSet<UserToken> UserTokens { get; set; }
        public DbSet<LoginLog> LoginLogs { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            // Primary Key tanımlamaları
            modelBuilder.Entity<User>().HasKey(u => u.UserId);
            modelBuilder.Entity<UserToken>().HasKey(t => t.TokenId);
            modelBuilder.Entity<LoginLog>().HasKey(l => l.LogId);

            // İlişki tanımlamaları
            modelBuilder.Entity<UserToken>()
                .HasOne<User>()
                .WithMany()
                .HasForeignKey(t => t.UserId);

            // Email için unique index
            modelBuilder.Entity<User>()
                .HasIndex(u => u.Email)
                .IsUnique();
        }
    }

    // UserToken modeli
    public class UserToken
    {
        public int TokenId { get; set; }
        public int UserId { get; set; }
        public string RefreshToken { get; set; }
        public DateTime RefreshTokenExpiry { get; set; }
        public DateTime CreatedAt { get; set; } = DateTime.Now;
    }

    // LoginLog modeli
    public class LoginLog
    {
        public int LogId { get; set; }
        public string Email { get; set; }
        public DateTime LoginTime { get; set; } = DateTime.Now;
        public string Status { get; set; }
        public string IPAddress { get; set; }
        public string UserAgent { get; set; }
    }

}
