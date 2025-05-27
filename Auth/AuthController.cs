using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using LibraryManagementSystem.Api.Models; // For ApplicationUser
using LibraryManagementSystem.Api.DTOs; // For UserRegistrationDto, UserLoginDto

namespace LibraryManagementSystem.Api.Controllers.Auth
{
    [Route("api/[controller]")] // Sets the base route for this controller to /api/Auth
    [ApiController] // Indicates that the controller responds to web API requests
    public class AuthController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration; // To access appsettings.json values

        public AuthController(
            UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        // POST: api/Auth/register
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] UserRegistrationDto model)
        {
            // Validate the input model using Data Annotations (FluentValidation will be added later for more robust validation)
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState); // Returns validation errors
            }

            // Check if user with this username or email already exists
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
            {
                return StatusCode(StatusCodes.Status409Conflict, new { Message = "User with this username already exists." });
            }

            userExists = await _userManager.FindByEmailAsync(model.Email);
            if (userExists != null)
            {
                return StatusCode(StatusCodes.Status409Conflict, new { Message = "User with this email already exists." });
            }

            // Create new ApplicationUser
            ApplicationUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(), // A unique ID for security purposes
                UserName = model.Username
            };

            // Create the user with the provided password
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                // If user creation fails, return a list of errors
                return StatusCode(StatusCodes.Status500InternalServerError, new { Message = "User creation failed! Please check user details and try again.", Errors = result.Errors.Select(e => e.Description) });
            }

            // Optional: Assign a default role, e.g., "User"
            // First, ensure the "User" role exists
            if (!await _roleManager.RoleExistsAsync("User"))
            {
                await _roleManager.CreateAsync(new IdentityRole("User"));
            }
            // Add the user to the "User" role
            await _userManager.AddToRoleAsync(user, "User");

            return StatusCode(StatusCodes.Status201Created, new { Message = "User created successfully!" });
        }

        // POST: api/Auth/login
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UserLoginDto model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            // Find the user by username
            var user = await _userManager.FindByNameAsync(model.Username);
            // Check if user exists and password is correct
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                // Get user's roles
                var userRoles = await _userManager.GetRolesAsync(user);

                // Create claims for JWT token
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName!), // User's username
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()), // Unique ID for the JWT token
                    new Claim(ClaimTypes.NameIdentifier, user.Id) // User's ID
                };

                // Add roles as claims
                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                // Get JWT secret key from configuration (appsettings.json)
                var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]!));
                if (authSigningKey.Key.Length < 32) // Basic check for key length (for HS256)
                {
                    // Log this or handle error appropriately in production
                    Console.WriteLine("Warning: JWT Secret key is too short. It should be at least 32 bytes for HS256.");
                }


                // Create JWT token
                var token = new JwtSecurityToken(
                    issuer: _configuration["JWT:ValidIssuer"],
                    audience: _configuration["JWT:ValidAudience"],
                    expires: DateTime.Now.AddHours(24), // Token valid for 24 hours (adjust as needed)
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

                // Return token and expiration time
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo
                });
            }
            return Unauthorized(new { Message = "Invalid username or password." });
        }

        // You might add a separate endpoint for role management (e.g., assigning admin roles) here later if needed.
        // POST: api/Auth/register-admin (example)
        [HttpPost("register-admin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] UserRegistrationDto model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }

            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
            {
                return StatusCode(StatusCodes.Status409Conflict, new { Message = "User with this username already exists." });
            }

            ApplicationUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Username
            };

            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new { Message = "User creation failed! Please check user details and try again.", Errors = result.Errors.Select(e => e.Description) });
            }

            // Ensure "Admin" role exists
            if (!await _roleManager.RoleExistsAsync("Admin"))
            {
                await _roleManager.CreateAsync(new IdentityRole("Admin"));
            }
            // Ensure "User" role exists (if not already created by regular registration)
            if (!await _roleManager.RoleExistsAsync("User"))
            {
                await _roleManager.CreateAsync(new IdentityRole("User"));
            }

            // Add to "Admin" role
            await _userManager.AddToRoleAsync(user, "Admin");
            // Optional: Add Admin user to "User" role as well, if Admin implies User permissions
            await _userManager.AddToRoleAsync(user, "User");


            return StatusCode(StatusCodes.Status201Created, new { Message = "Admin user created successfully!" });
        }
    }
}