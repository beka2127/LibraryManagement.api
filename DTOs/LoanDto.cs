namespace LibraryManagementSystem.Api.DTOs
{
    public class LoanDto
    {
        public int Id { get; set; }
        public int BookId { get; set; }
        public string BookTitle { get; set; } = string.Empty; // To show book title directly
        public int BorrowerId { get; set; }
        public string BorrowerName { get; set; } = string.Empty; // To show borrower name directly
        public DateTime BorrowDate { get; set; }
        public DateTime DueDate { get; set; }
        public DateTime? ReturnDate { get; set; }
        public bool IsOverdue { get; set; }
    }
}