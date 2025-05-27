using System.ComponentModel.DataAnnotations;

namespace LibraryManagementSystem.Api.DTOs
{
    public class UpdateBorrowerDto
    {
        [MaxLength(100, ErrorMessage = "Name cannot exceed 100 characters.")]
        public string? Name { get; set; }

        [EmailAddress(ErrorMessage = "Invalid email format.")]
        [MaxLength(150, ErrorMessage = "ContactInfo cannot exceed 150 characters.")]
        public string? ContactInfo { get; set; }
    }
}