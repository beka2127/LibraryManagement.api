using System.ComponentModel.DataAnnotations;

namespace LibraryManagementSystem.Api.DTOs
{
    public class CreateLoanDto
    {
        [Required(ErrorMessage = "Book ID is required.")]
        [Range(1, int.MaxValue, ErrorMessage = "Book ID must be a positive integer.")]
        public int BookId { get; set; }

        [Required(ErrorMessage = "Borrower ID is required.")]
        [Range(1, int.MaxValue, ErrorMessage = "Borrower ID must be a positive integer.")]
        public int BorrowerId { get; set; }

        [Required(ErrorMessage = "Borrow date is required.")]
        public DateTime BorrowDate { get; set; } = DateTime.UtcNow; // Default to UtcNow

        [Required(ErrorMessage = "Due date is required.")]
        public DateTime DueDate { get; set; }
    }
}