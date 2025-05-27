using Microsoft.AspNetCore.Identity;

namespace LibraryManagementSystem.Api.Models
{
    // ApplicationUser will extend IdentityUser, which provides all the standard fields for user management (username, email, password hash, etc.)
    public class ApplicationUser : IdentityUser
    {
        // You can add additional properties here specific to your library users if needed.
        // For example:
        // public string? FullName { get; set; }
        // public DateTime? DateRegistered { get; set; }
    }
}