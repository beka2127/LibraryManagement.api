using System.ComponentModel.DataAnnotations;

namespace LibraryManagementSystem.Api.DTOs
{
    public class ReturnLoanDto
    {
        [Required(ErrorMessage = "Loan ID is required.")]
        [Range(1, int.MaxValue, ErrorMessage = "Loan ID must be a positive integer.")]
        public int LoanId { get; set; }

        [Required(ErrorMessage = "Return date is required.")]
        public DateTime ReturnDate { get; set; } = DateTime.UtcNow; // Default to UtcNow
    }
}