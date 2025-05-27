// Top-level using statements
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Microsoft.OpenApi.Models; // For Swagger
using LibraryManagementSystem.Api.Data; // Your DbContext namespace
using LibraryManagementSystem.Api.Models; // Your ApplicationUser namespace
// Add AutoMapper and FluentValidation usings if you installed them in Step 2,
// though we haven't configured them yet in Program.cs.
// For now, these are not strictly necessary unless you start using them in your code.
// using AutoMapper;
// using FluentValidation;
// using FluentValidation.AspNetCore;
using AutoMapper; // Add this line
using LibraryManagementSystem.Api.Repositories; // Add this line


var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

// --- Database Configuration (using SQLite example) ---
// Get the connection string from appsettings.json
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
// Register ApplicationDbContext with the Dependency Injection container
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(connectionString)); // Use .UseSqlServer() if you installed SQL Server provider

// --- Identity Configuration ---
// Add Identity services to the container, configuring them to use ApplicationUser and IdentityRole
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    // Optional: Configure Identity options like password requirements, lockout settings etc.
    // These are good for development to avoid overly complex passwords during testing
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireNonAlphanumeric = false; // Set to true for production-level security
    options.Password.RequireUppercase = true;
    options.Password.RequiredLength = 6; // Set to a higher value for production (e.g., 8 or 10)
    options.User.RequireUniqueEmail = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>() // Tell Identity to use ApplicationDbContext for storing user data
.AddDefaultTokenProviders(); // For password reset tokens, email confirmation tokens etc.

// --- JWT Authentication Configuration ---
// Configure the authentication scheme to use JWT Bearer tokens
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme; // Default scheme for authentication
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;   // Default scheme for challenge (e.g., when unauthorized)
    options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;          // Default scheme when no specific scheme is mentioned
})
.AddJwtBearer(options =>
{
    options.SaveToken = true; // Save the token in AuthenticationProperties
    options.RequireHttpsMetadata = false; // Set to 'true' in production for security!
                                          // 'false' is okay for local HTTP testing.
    options.TokenValidationParameters = new TokenValidationParameters()
    {
        ValidateIssuer = true, // Validate the server that created the token
        ValidateAudience = true, // Validate the recipient of the token
        ValidAudience = builder.Configuration["JWT:ValidAudience"], // The audience defined in appsettings.json
        ValidIssuer = builder.Configuration["JWT:ValidIssuer"],   // The issuer defined in appsettings.json
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(builder.Configuration["JWT:Secret"]!)) // The secret key for signing
    };
});

// --- Add CORS (Cross-Origin Resource Sharing) Policy ---
// This is essential if your frontend (bonus client) will be hosted on a different domain or port
// than your backend API. It allows your browser to make requests to the API.
// Define a policy name, e.g., "_myAllowSpecificOrigins"
var MyAllowSpecificOrigins = "_myAllowSpecificOrigins";
builder.Services.AddCors(options =>
{
    options.AddPolicy(name: MyAllowSpecificOrigins,
                      policy =>
                      {
                          // For development, allow any origin, any header, and any method.
                          // In a production environment, you should strictly limit .WithOrigins()
                          // to your actual frontend application's domain(s).
                          policy.AllowAnyOrigin() // Example: .WithOrigins("http://localhost:4200", "https://yourfrontend.com")
                                .AllowAnyHeader()
                                .AllowAnyMethod();
                      });
});


builder.Services.AddControllers();
// ... other services ...

builder.Services.AddControllers();

// Add AutoMapper service, looking for profiles in the current assembly
builder.Services.AddAutoMapper(typeof(Program).Assembly); // This tells AutoMapper to scan the current assembly for mapping profiles (like your MappingProfile.cs)

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
// ... rest of Program.cs ...
// Adds controller-based API functionality
// ... other services ...

builder.Services.AddAutoMapper(typeof(Program).Assembly);

// Register Unit of Work as a scoped service.
// Scoped services are created once per client request (HTTP request),
// which is ideal for DbContext and UnitOfWork to ensure consistency within a request.
builder.Services.AddScoped<IUnitOfWork, UnitOfWork>();

builder.Services.AddControllers();

// ... rest of Program.cs ...

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
// Configure Swagger to include a JWT authorization option in the UI
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Library Management API", Version = "v1" });

    // Define the security scheme for JWT Bearer tokens in Swagger UI
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Example: \"Authorization: Bearer {token}\"",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer" // The name of the authentication scheme to be used in 'securitySchemes'
    });

    // Add security requirement for all operations in Swagger UI, meaning you can authorize globally
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer" // Refers to the security definition named "Bearer"
                }
            },
            Array.Empty<string>() // Empty array means no specific scopes/roles are required globally by default
        }
    });
});

var app = builder.Build();

// Configure the HTTP request pipeline. // This defines the order of middleware execution.

if (app.Environment.IsDevelopment())
{
    app.UseDeveloperExceptionPage(); // Provides detailed error pages in development
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "Library Management API V1");
    });
}
else
{
    // In production, use a more user-friendly error handling.
    // You might create a custom error handling middleware or use app.UseExceptionHandler("/error")
    // and map an ErrorController endpoint.
    app.UseExceptionHandler("/error"); // Will need to define an /error endpoint later
    app.UseHsts(); // Adds Strict-Transport-Security header for security
}

app.UseHttpsRedirection(); // Redirects HTTP requests to HTTPS

app.UseRouting(); // Identifies which endpoint (controller action) to run based on the URL. MUST be before UseCors, UseAuthentication, UseAuthorization.

// --- Apply the CORS policy ---
// This must be placed between UseRouting() and UseAuthentication()/UseAuthorization().
app.UseCors(MyAllowSpecificOrigins);

app.UseAuthentication(); // Adds the authentication middleware to the pipeline. It checks for tokens.
app.UseAuthorization(); // Adds the authorization middleware to the pipeline. It checks if the user has permission.

app.MapControllers(); // Maps incoming requests to the appropriate controller actions.

app.Run();

// Optional: You might want to seed an initial user/roles for testing.
// This block ensures migrations are applied and a default admin user is created on startup.
// IMPORTANT: For production deployments, handle migrations and seeding separately (e.g., via command line or migration scripts).
// For development, this is convenient.
/*
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    try
    {
        var context = services.GetRequiredService<ApplicationDbContext>();
        // Apply pending migrations automatically
        context.Database.Migrate();

        var userManager = services.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = services.GetRequiredService<RoleManager<IdentityRole>>();

        // Seed roles and an admin user (you would create a separate static class for this)
        // await DataSeeder.SeedRolesAndAdminUser(userManager, roleManager);
    }
    catch (Exception ex)
    {
        var logger = services.GetRequiredService<ILogger<Program>>();
        logger.LogError(ex, "An error occurred while seeding the database or applying migrations.");
    }
}
*/