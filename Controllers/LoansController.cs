using AutoMapper;
using LibraryManagementSystem.Api.DTOs;
using LibraryManagementSystem.Api.Models;
using LibraryManagementSystem.Api.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore; // For .Include()

namespace LibraryManagementSystem.Api.Controllers
{
    [Route("api/[controller]")] // Base route: /api/loans
    [ApiController]
    [Authorize] // All endpoints in this controller require authentication
    public class LoansController : ControllerBase
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;

        public LoansController(IUnitOfWork unitOfWork, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        // GET: api/loans
        // Optionally, you might want to filter/paginate this in a real app
        [HttpGet]
        public async Task<ActionResult<IEnumerable<LoanDto>>> GetLoans()
        {
            // Include related Book and Borrower data for the DTO mapping
            var loans = await _unitOfWork.Loans.GetAllAsync();
            // Ensure Book and Borrower are loaded for AutoMapper
            foreach (var loan in loans)
            {
                await _unitOfWork.Books.GetByIdAsync(loan.BookId); // Load Book
                await _unitOfWork.Borrowers.GetByIdAsync(loan.BorrowerId); // Load Borrower
            }

            // A more efficient way to load related data directly within the repository is preferred for large datasets.
            // For example, by having a custom method in ILoanRepository or using Include in a custom Find method:
            // var loans = await _unitOfWork.Loans.GetLoansWithBookAndBorrowerAsync();

            return Ok(_mapper.Map<IEnumerable<LoanDto>>(loans));
        }

        // GET: api/loans/{id}
        [HttpGet("{id}")]
        public async Task<ActionResult<LoanDto>> GetLoan(int id)
        {
            var loan = await _unitOfWork.Loans.GetByIdAsync(id);

            if (loan == null)
            {
                return NotFound(new { Message = "Loan not found." });
            }

            // Load related Book and Borrower to populate DTO
            await _unitOfWork.Books.GetByIdAsync(loan.BookId);
            await _unitOfWork.Borrowers.GetByIdAsync(loan.BorrowerId);

            return Ok(_mapper.Map<LoanDto>(loan));
        }

        // POST: api/loans/borrow
        [HttpPost("borrow")]
        public async Task<ActionResult<LoanDto>> BorrowBook([FromBody] CreateLoanDto createLoanDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // 1. Check if Book and Borrower exist
            var book = await _unitOfWork.Books.GetByIdAsync(createLoanDto.BookId);
            if (book == null)
            {
                return NotFound(new { Message = "Book not found." });
            }

            var borrower = await _unitOfWork.Borrowers.GetByIdAsync(createLoanDto.BorrowerId);
            if (borrower == null)
            {
                return NotFound(new { Message = "Borrower not found." });
            }

            // 2. Check if book is available
            if (book.AvailableQuantity <= 0)
            {
                return BadRequest(new { Message = "Book is currently out of stock." });
            }

            // 3. Prevent multiple active loans of the same book by the same borrower (optional, depends on policy)
            // var existingActiveLoan = await _unitOfWork.Loans.FindAsync(l =>
            //     l.BookId == createLoanDto.BookId &&
            //     l.BorrowerId == createLoanDto.BorrowerId &&
            //     l.ReturnDate == null);
            // if (existingActiveLoan.Any())
            // {
            //     return Conflict(new { Message = "This borrower already has an active loan for this book." });
            // }


            // 4. Create Loan entity
            var loan = _mapper.Map<Loan>(createLoanDto);
            loan.BorrowDate = createLoanDto.BorrowDate.ToUniversalTime(); // Ensure UTC
            loan.DueDate = createLoanDto.DueDate.ToUniversalTime();     // Ensure UTC

            // 5. Decrement book's available quantity
            book.AvailableQuantity--;
            _unitOfWork.Books.Update(book); // Mark book as updated

            // 6. Add loan and save all changes in one transaction
            await _unitOfWork.Loans.AddAsync(loan);
            await _unitOfWork.SaveChangesAsync(); // This commits both book update and loan addition

            // Load related entities for DTO mapping if not already loaded by EF's tracking
            loan.Book = book;
            loan.Borrower = borrower;

            var loanDto = _mapper.Map<LoanDto>(loan);
            return CreatedAtAction(nameof(GetLoan), new { id = loanDto.Id }, loanDto);
        }

        // POST: api/loans/return
        [HttpPost("return")]
        public async Task<IActionResult> ReturnBook([FromBody] ReturnLoanDto returnLoanDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var loan = await _unitOfWork.Loans.GetByIdAsync(returnLoanDto.LoanId);
            if (loan == null)
            {
                return NotFound(new { Message = "Loan not found." });
            }

            if (loan.ReturnDate != null)
            {
                return BadRequest(new { Message = "Book has already been returned for this loan." });
            }

            // 1. Update loan record with return date
            loan.ReturnDate = returnLoanDto.ReturnDate.ToUniversalTime(); // Ensure UTC
            _unitOfWork.Loans.Update(loan);

            // 2. Increment book's available quantity
            var book = await _unitOfWork.Books.GetByIdAsync(loan.BookId);
            if (book != null) // Should not be null if loan exists
            {
                book.AvailableQuantity++;
                _unitOfWork.Books.Update(book);
            }

            // 3. Save all changes
            await _unitOfWork.SaveChangesAsync();

            return NoContent(); // 204 No Content for successful operation
        }

        // GET: api/loans/overdue
        [HttpGet("overdue")]
        public async Task<ActionResult<IEnumerable<LoanDto>>> GetOverdueLoans()
        {
            // Get loans that have a DueDate in the past and no ReturnDate
            var overdueLoans = await _unitOfWork.Loans.FindAsync(l => l.DueDate < DateTime.UtcNow && l.ReturnDate == null);

            // Load related Book and Borrower data for the DTO mapping
            foreach (var loan in overdueLoans)
            {
                await _unitOfWork.Books.GetByIdAsync(loan.BookId);
                await _unitOfWork.Borrowers.GetByIdAsync(loan.BorrowerId);
            }

            // Map to DTOs and set IsOverdue flag
            var overdueLoanDtos = _mapper.Map<IEnumerable<LoanDto>>(overdueLoans);
            return Ok(overdueLoanDtos);
        }
    }
}