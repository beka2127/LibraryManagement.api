using System.ComponentModel.DataAnnotations; // For data annotations if you choose to use them (not strictly necessary with FluentValidation)

namespace LibraryManagementSystem.Api.Models
{
    public class Book
    {
        // Primary Key for the Book entity
        public int Id { get; set; }

        // Title of the book. Initialized to string.Empty to handle nullable reference types warnings.
        public string Title { get; set; } = string.Empty;

        // Author(s) of the book
        public string Author { get; set; } = string.Empty;

        // International Standard Book Number
        public string ISBN { get; set; } = string.Empty;

        // Total number of copies of this book in the library
        public int Quantity { get; set; }

        // Number of copies currently available for borrowing
        public int AvailableQuantity { get; set; }

        // Navigation property: A book can be part of many loan transactions (one-to-many relationship)
        public ICollection<Loan> Loans { get; set; } = new List<Loan>();
    }
}