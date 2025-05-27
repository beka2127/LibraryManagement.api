using LibraryManagementSystem.Api.Data; // Your DbContext namespace
using LibraryManagementSystem.Api.Models; // Your Models namespace

namespace LibraryManagementSystem.Api.Repositories
{
    // UnitOfWork implements the IUnitOfWork interface
    public class UnitOfWork : IUnitOfWork
    {
        private readonly ApplicationDbContext _context;
        private IGenericRepository<Book>? _books; // Nullable backing fields
        private IGenericRepository<Borrower>? _borrowers;
        private IGenericRepository<Loan>? _loans;

        public UnitOfWork(ApplicationDbContext context)
        {
            _context = context;
        }

        // Lazy initialization for repositories to avoid creating them if not needed
        public IGenericRepository<Book> Books => _books ??= new GenericRepository<Book>(_context);
        public IGenericRepository<Borrower> Borrowers => _borrowers ??= new GenericRepository<Borrower>(_context);
        public IGenericRepository<Loan> Loans => _loans ??= new GenericRepository<Loan>(_context);

        public async Task<int> SaveChangesAsync()
        {
            return await _context.SaveChangesAsync();
        }

        // Dispose method to properly dispose of the DbContext
        public void Dispose()
        {
            _context.Dispose();
            GC.SuppressFinalize(this); // Tell GC not to call finalizer twice
        }
    }
}