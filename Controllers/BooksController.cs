using AutoMapper;
using LibraryManagementSystem.Api.DTOs;
using LibraryManagementSystem.Api.Models;
using LibraryManagementSystem.Api.Repositories; // For IUnitOfWork
using Microsoft.AspNetCore.Authorization; // For [Authorize] attribute
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore; // For .Include()

namespace LibraryManagementSystem.Api.Controllers
{
    [Route("api/[controller]")] // Base route: /api/books
    [ApiController]
    [Authorize] // All endpoints in this controller require authentication
    public class BooksController : ControllerBase
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;

        public BooksController(IUnitOfWork unitOfWork, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        // GET: api/books
        [HttpGet]
        public async Task<ActionResult<IEnumerable<BookDto>>> GetBooks()
        {
            var books = await _unitOfWork.Books.GetAllAsync();
            return Ok(_mapper.Map<IEnumerable<BookDto>>(books));
        }

        // GET: api/books/{id}
        [HttpGet("{id}")]
        public async Task<ActionResult<BookDto>> GetBook(int id)
        {
            var book = await _unitOfWork.Books.GetByIdAsync(id);

            if (book == null)
            {
                return NotFound(new { Message = "Book not found." });
            }

            return Ok(_mapper.Map<BookDto>(book));
        }

        // POST: api/books
        // [Authorize(Roles = "Admin")] // Example: Only Admin can add books
        [HttpPost]
        public async Task<ActionResult<BookDto>> CreateBook([FromBody] CreateBookDto createBookDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // Check for duplicate ISBN
            var existingBook = await _unitOfWork.Books.FindAsync(b => b.ISBN == createBookDto.ISBN);
            if (existingBook.Any())
            {
                return Conflict(new { Message = "A book with this ISBN already exists." });
            }

            var book = _mapper.Map<Book>(createBookDto);
            book.AvailableQuantity = book.Quantity; // Initialize available quantity upon creation

            await _unitOfWork.Books.AddAsync(book);
            await _unitOfWork.SaveChangesAsync(); // Commit changes to database

            var bookDto = _mapper.Map<BookDto>(book);
            // Return 201 Created and the location of the new resource
            return CreatedAtAction(nameof(GetBook), new { id = bookDto.Id }, bookDto);
        }

        // PUT: api/books/{id}
        // [Authorize(Roles = "Admin")] // Example: Only Admin can update books
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateBook(int id, [FromBody] UpdateBookDto updateBookDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var book = await _unitOfWork.Books.GetByIdAsync(id);
            if (book == null)
            {
                return NotFound(new { Message = "Book not found." });
            }

            // If ISBN is updated, check for duplicates with other books
            if (!string.IsNullOrEmpty(updateBookDto.ISBN) && updateBookDto.ISBN != book.ISBN)
            {
                var existingBookWithSameISBN = await _unitOfWork.Books.FindAsync(b => b.ISBN == updateBookDto.ISBN && b.Id != id);
                if (existingBookWithSameISBN.Any())
                {
                    return Conflict(new { Message = "Another book with this ISBN already exists." });
                }
            }

            // Update properties using AutoMapper. This handles nullable properties correctly.
            _mapper.Map(updateBookDto, book);

            // Adjust AvailableQuantity if Quantity is updated and it makes sense (e.g., if Quantity decreased)
            // More complex logic might be needed here to ensure AvailableQuantity doesn't go below 0
            // For simplicity, we assume you manage loans which will decrement/increment AvailableQuantity
            if (updateBookDto.Quantity.HasValue)
            {
                // This logic assumes you are only increasing Quantity or that decreases won't affect current loans below 0
                // A more robust system would check active loans before reducing quantity below current 'available'
                book.AvailableQuantity = updateBookDto.Quantity.Value;
            }

            _unitOfWork.Books.Update(book); // Mark the entity as modified
            await _unitOfWork.SaveChangesAsync(); // Commit changes

            return NoContent(); // 204 No Content typically for successful PUT operations
        }

        // DELETE: api/books/{id}
        // [Authorize(Roles = "Admin")] // Example: Only Admin can delete books
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteBook(int id)
        {
            var book = await _unitOfWork.Books.GetByIdAsync(id);
            if (book == null)
            {
                return NotFound(new { Message = "Book not found." });
            }

            // Before deleting a book, you might want to check if there are any active loans for it.
            // For simplicity, due to cascade delete, associated loans will be deleted.
            // However, in a real system, you might prevent deletion if active loans exist.
            // Example check:
            // var activeLoans = await _unitOfWork.Loans.FindAsync(l => l.BookId == id && l.ReturnDate == null);
            // if (activeLoans.Any())
            // {
            //     return BadRequest(new { Message = "Cannot delete book. There are active loans associated with it." });
            // }


            _unitOfWork.Books.Delete(book); // Mark for deletion
            await _unitOfWork.SaveChangesAsync(); // Commit changes

            return NoContent(); // 204 No Content for successful deletion
        }
    }
}