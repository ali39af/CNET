using Microsoft.EntityFrameworkCore;

namespace CNET
{
    public class AppDbContext : DbContext
    {
        public DbSet<Domain> Domains { get; set; }
        public DbSet<HotspotUser> HotspotUsers { get; set; }

        public static string DataSource = "cnet.db";

        protected override void OnConfiguring(DbContextOptionsBuilder options)
            => options.UseSqlite($"Data Source={DataSource}");

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            modelBuilder.Entity<Domain>()
                .HasIndex(d => d.Match)
                .IsUnique();

            modelBuilder.Entity<HotspotUser>()
                .HasIndex(u => u.Username)
                .IsUnique();
        }
    }
}
