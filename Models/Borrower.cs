namespace LibraryManagementSystem.Api.Models
{
    public class Borrower
    {
        // Primary Key for the Borrower entity
        public int Id { get; set; }

        // Name of the borrower
        public string Name { get; set; } = string.Empty;

        // Contact information for the borrower (e.g., email address, phone number)
        public string ContactInfo { get; set; } = string.Empty;

        // Navigation property: A borrower can have many loan transactions (one-to-many relationship)
        public ICollection<Loan> Loans { get; set; } = new List<Loan>();
    }
}