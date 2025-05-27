namespace LibraryManagementSystem.Api.DTOs
{
    public class BorrowerDto
    {
        public int Id { get; set; }
        public string Name { get; set; } = string.Empty;
        public string ContactInfo { get; set; } = string.Empty;
    }
}