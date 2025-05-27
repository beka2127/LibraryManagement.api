using AutoMapper;
using LibraryManagementSystem.Api.Models;
using LibraryManagementSystem.Api.DTOs;

namespace LibraryManagementSystem.Api.MappingProfiles
{
    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            // Book Mappings
            CreateMap<Book, BookDto>().ReverseMap(); // Maps Book to BookDto and vice-versa
            CreateMap<CreateBookDto, Book>()
                .ForMember(dest => dest.AvailableQuantity, opt => opt.MapFrom(src => src.Quantity)); // When creating a book, AvailableQuantity starts as Quantity
            CreateMap<UpdateBookDto, Book>()
                .ForAllMembers(opt => opt.Condition((src, dest, srcMember) => srcMember != null)); // Ignore nulls for partial updates

            // Borrower Mappings
            CreateMap<Borrower, BorrowerDto>().ReverseMap();
            CreateMap<CreateBorrowerDto, Borrower>();
            CreateMap<UpdateBorrowerDto, Borrower>()
                .ForAllMembers(opt => opt.Condition((src, dest, srcMember) => srcMember != null));

            // Loan Mappings
            // Map from Loan entity to LoanDto, including properties from related Book and Borrower
            CreateMap<Loan, LoanDto>()
                .ForMember(dest => dest.BookTitle, opt => opt.MapFrom(src => src.Book.Title))
                .ForMember(dest => dest.BorrowerName, opt => opt.MapFrom(src => src.Borrower.Name))
                .ForMember(dest => dest.IsOverdue, opt => opt.MapFrom(src => src.IsOverdue)); // Map the computed property
            CreateMap<CreateLoanDto, Loan>();
            CreateMap<ReturnLoanDto, Loan>(); // For updating an existing loan with return info

            // User Mappings (for registration, if you want a UserDto later for output)
            // If you want to return a simplified user DTO after registration/login (without password hash etc.)
            // CreateMap<ApplicationUser, UserDto>(); // You would define UserDto separately
        }
    }
}