using System.Linq.Expressions; // For Expression<Func<T, bool>>

namespace LibraryManagementSystem.Api.Repositories
{
    // IGenericRepository defines common CRUD operations for any entity
    public interface IGenericRepository<T> where T : class
    {
        Task<IEnumerable<T>> GetAllAsync();
        Task<T?> GetByIdAsync(int id); // T? indicates it can return null
        Task AddAsync(T entity);
        void Update(T entity); // No async for simple update, EF tracks changes
        void Delete(T entity); // No async for simple delete, EF tracks changes
        Task<IEnumerable<T>> FindAsync(Expression<Func<T, bool>> predicate); // For filtered queries
        Task<bool> ExistsAsync(Expression<Func<T, bool>> predicate); // Check if entity exists
    }
}