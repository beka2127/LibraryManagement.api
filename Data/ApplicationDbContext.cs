using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using LibraryManagementSystem.Api.Models; // Make sure this namespace matches your Models folder

namespace LibraryManagementSystem.Api.Data
{
    // ApplicationDbContext inherits from IdentityDbContext to include Identity tables (users, roles, etc.)
    // It's generic, taking ApplicationUser as the user type.
    public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        // DbSet properties represent your database tables.
        // Each DbSet will correspond to one of your model classes.
        public DbSet<Book> Books { get; set; }
        public DbSet<Borrower> Borrowers { get; set; }
        public DbSet<Loan> Loans { get; set; }

        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder); // Must call base.OnModelCreating for IdentityDbContext

            // Configure relationships and other model-specific settings here.
            // For example, ensuring cascade delete behavior for loans:

            // When a Book is deleted, its associated Loans should also be deleted.
            builder.Entity<Loan>()
                .HasOne(l => l.Book)            // A Loan has one Book
                .WithMany(b => b.Loans)         // A Book has many Loans
                .HasForeignKey(l => l.BookId)   // BookId is the foreign key in Loan
                .OnDelete(DeleteBehavior.Cascade); // If a Book is deleted, associated Loans are also deleted.

            // When a Borrower is deleted, their associated Loans should also be deleted.
            builder.Entity<Loan>()
                .HasOne(l => l.Borrower)         // A Loan has one Borrower
                .WithMany(b => b.Loans)          // A Borrower has many Loans
                .HasForeignKey(l => l.BorrowerId) // BorrowerId is the foreign key in Loan
                .OnDelete(DeleteBehavior.Cascade); // If a Borrower is deleted, associated Loans are also deleted.

            // You can add more configurations here, e.g., unique constraints,
            // data seeding, different precision for decimal types, etc.
        }
    }
}