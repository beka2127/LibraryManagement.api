namespace LibraryManagementSystem.Api.Models
{
    public class Loan
    {
        // Primary Key for the Loan entity
        public int Id { get; set; }

        // Foreign Key to the Book entity
        public int BookId { get; set; }
        // Navigation property to the associated Book
        public Book Book { get; set; } = null!; // 'null!' tells the compiler this will not be null after loading from DB

        // Foreign Key to the Borrower entity
        public int BorrowerId { get; set; }
        // Navigation property to the associated Borrower
        public Borrower Borrower { get; set; } = null!; // 'null!' tells the compiler this will not be null after loading from DB

        // Date the book was borrowed
        public DateTime BorrowDate { get; set; }

        // Date the book is due back
        public DateTime DueDate { get; set; }

        // Date the book was actually returned (nullable, because it's not set when the loan is created)
        public DateTime? ReturnDate { get; set; }

        // Helper property to determine if the loan is overdue. This property will NOT be stored in the database.
        // It's calculated on-the-fly based on ReturnDate and DueDate.
        public bool IsOverdue => ReturnDate == null && DateTime.UtcNow > DueDate;
    }
}