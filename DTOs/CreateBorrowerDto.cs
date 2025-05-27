using System.ComponentModel.DataAnnotations;

namespace LibraryManagementSystem.Api.DTOs
{
    public class CreateBorrowerDto
    {
        [Required(ErrorMessage = "Borrower name is required.")]
        [MaxLength(100, ErrorMessage = "Name cannot exceed 100 characters.")]
        public string Name { get; set; } = string.Empty;

        [Required(ErrorMessage = "Contact information is required.")]
        [EmailAddress(ErrorMessage = "Invalid email format.")] // Assuming ContactInfo is an email
        [MaxLength(150, ErrorMessage = "ContactInfo cannot exceed 150 characters.")]
        public string ContactInfo { get; set; } = string.Empty;
    }
}