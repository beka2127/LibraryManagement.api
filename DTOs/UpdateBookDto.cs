using System.ComponentModel.DataAnnotations;

namespace LibraryManagementSystem.Api.DTOs
{
    public class UpdateBookDto
    {
        // Id is usually part of the route for updates (e.g., PUT /api/books/{id})
        // but can also be included in the DTO if needed.

        [MaxLength(200, ErrorMessage = "Title cannot exceed 200 characters.")]
        public string? Title { get; set; } // Nullable because it might not be provided for a partial update

        [MaxLength(200, ErrorMessage = "Author cannot exceed 200 characters.")]
        public string? Author { get; set; }

        [StringLength(13, MinimumLength = 10, ErrorMessage = "ISBN must be between 10 and 13 characters.")]
        public string? ISBN { get; set; }

        [Range(0, int.MaxValue, ErrorMessage = "Quantity cannot be negative.")]
        public int? Quantity { get; set; } // Nullable for partial updates
    }
}