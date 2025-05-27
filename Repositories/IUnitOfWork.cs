using LibraryManagementSystem.Api.Models; // Your Models namespace

namespace LibraryManagementSystem.Api.Repositories
{
    // IUnitOfWork orchestrates repositories and manages transaction across them.
    public interface IUnitOfWork : IDisposable
    {
        // Properties for specific repositories
        IGenericRepository<Book> Books { get; }
        IGenericRepository<Borrower> Borrowers { get; }
        IGenericRepository<Loan> Loans { get; }

        // Method to save all changes made in the current unit of work
        Task<int> SaveChangesAsync();
    }
}