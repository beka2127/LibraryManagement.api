using AutoMapper;
using LibraryManagementSystem.Api.DTOs;
using LibraryManagementSystem.Api.Models;
using LibraryManagementSystem.Api.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace LibraryManagementSystem.Api.Controllers
{
    [Route("api/[controller]")] // Base route: /api/borrowers
    [ApiController]
    [Authorize] // All endpoints in this controller require authentication
    public class BorrowersController : ControllerBase
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IMapper _mapper;

        public BorrowersController(IUnitOfWork unitOfWork, IMapper mapper)
        {
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        // GET: api/borrowers
        [HttpGet]
        public async Task<ActionResult<IEnumerable<BorrowerDto>>> GetBorrowers()
        {
            var borrowers = await _unitOfWork.Borrowers.GetAllAsync();
            return Ok(_mapper.Map<IEnumerable<BorrowerDto>>(borrowers));
        }

        // GET: api/borrowers/{id}
        [HttpGet("{id}")]
        public async Task<ActionResult<BorrowerDto>> GetBorrower(int id)
        {
            var borrower = await _unitOfWork.Borrowers.GetByIdAsync(id);

            if (borrower == null)
            {
                return NotFound(new { Message = "Borrower not found." });
            }

            return Ok(_mapper.Map<BorrowerDto>(borrower));
        }

        // POST: api/borrowers
        [HttpPost]
        public async Task<ActionResult<BorrowerDto>> CreateBorrower([FromBody] CreateBorrowerDto createBorrowerDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // Optional: Check for duplicate contact info (e.g., email)
            var existingBorrower = await _unitOfWork.Borrowers.FindAsync(b => b.ContactInfo == createBorrowerDto.ContactInfo);
            if (existingBorrower.Any())
            {
                return Conflict(new { Message = "A borrower with this contact information already exists." });
            }

            var borrower = _mapper.Map<Borrower>(createBorrowerDto);

            await _unitOfWork.Borrowers.AddAsync(borrower);
            await _unitOfWork.SaveChangesAsync();

            var borrowerDto = _mapper.Map<BorrowerDto>(borrower);
            return CreatedAtAction(nameof(GetBorrower), new { id = borrowerDto.Id }, borrowerDto);
        }

        // PUT: api/borrowers/{id}
        [HttpPut("{id}")]
        public async Task<IActionResult> UpdateBorrower(int id, [FromBody] UpdateBorrowerDto updateBorrowerDto)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var borrower = await _unitOfWork.Borrowers.GetByIdAsync(id);
            if (borrower == null)
            {
                return NotFound(new { Message = "Borrower not found." });
            }

            // If ContactInfo is updated, check for duplicates with other borrowers
            if (!string.IsNullOrEmpty(updateBorrowerDto.ContactInfo) && updateBorrowerDto.ContactInfo != borrower.ContactInfo)
            {
                var existingBorrowerWithSameContact = await _unitOfWork.Borrowers.FindAsync(b => b.ContactInfo == updateBorrowerDto.ContactInfo && b.Id != id);
                if (existingBorrowerWithSameContact.Any())
                {
                    return Conflict(new { Message = "Another borrower with this contact information already exists." });
                }
            }

            _mapper.Map(updateBorrowerDto, borrower);

            _unitOfWork.Borrowers.Update(borrower);
            await _unitOfWork.SaveChangesAsync();

            return NoContent();
        }

        // DELETE: api/borrowers/{id}
        [HttpDelete("{id}")]
        public async Task<IActionResult> DeleteBorrower(int id)
        {
            var borrower = await _unitOfWork.Borrowers.GetByIdAsync(id);
            if (borrower == null)
            {
                return NotFound(new { Message = "Borrower not found." });
            }

            // Important: Before deleting a borrower, you should check if they have any active loans.
            // Preventing deletion if active loans exist is good practice to maintain data integrity.
            var activeLoans = await _unitOfWork.Loans.FindAsync(l => l.BorrowerId == id && l.ReturnDate == null);
            if (activeLoans.Any())
            {
                return BadRequest(new { Message = "Cannot delete borrower. There are active loans associated with this borrower." });
            }

            _unitOfWork.Borrowers.Delete(borrower);
            await _unitOfWork.SaveChangesAsync();

            return NoContent();
        }
    }
}