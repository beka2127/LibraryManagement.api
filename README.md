# LibraryManagement.api
c#
## Installation

1.  **Navigate to the `LibraryManagementSystem.Api` directory:**
    ```bash
    cd path/to/your/repo/LibraryManagementSystem.Api
    ```
2.  **Restore dependencies:**
    ```bash
    dotnet restore
    ```

## Database Setup

1.  **Configure Connection String:**
    * Open `appsettings.json` (and `appsettings.Development.json`).
    * Update the `DefaultConnection` string to connect to your local SQL Server instance.
        ```json
        "ConnectionStrings": {
          "DefaultConnection": "Server=YourServerName;Database=LibraryDb;Trusted_Connection=True;MultipleActiveResultSets=true;TrustServerCertificate=True"
        },
        ```
        *Remember to replace `YourServerName`.*
2.  **Apply Migrations:**
    * Open a terminal in the `LibraryManagementSystem.Api` directory.
    * Run the following command to create the database and apply all pending migrations:
        ```bash
        dotnet ef database update
        ```
    * *If you need to create initial migrations or manage them:*
        * `dotnet ef migrations add InitialCreate` (only if no migrations exist)
        * `dotnet build`

## Configuration

1.  **JWT Settings:**
    * In `appsettings.json`, configure your JWT settings. **In a production environment, ensure the `Key` is very strong and secured (e.g., via environment variables).**
        ```json
        "Jwt": {
          "Issuer": "LibraryAppIssuer",
          "Audience": "LibraryAppAudience",
          "Key": "ThisIsAVeryStrongAndSecretKeyForJwtAuthenticationWhichShouldBeLongEnough"
        },
        ```
2.  **CORS Policy:**
    * Open `Program.cs`.
    * Ensure the CORS policy named `_myAllowSpecificOrigins` is configured to allow requests from your frontend's URL (`http://localhost:3000`).
    * Verify the order of middleware: `app.UseCors()` must be called before `app.UseAuthentication()` and `app.UseAuthorization()`.

## Running the API

* **From terminal:**
    ```bash
    dotnet run
    ```
* **From Visual Studio:**
    * Open the `LibraryManagementSystem.Api.csproj` in Visual Studio.
    * Press `F5` to run the application.

Upon running, the API will typically open its **Swagger UI** in your default browser (e.g., `https://localhost:7086/swagger`). This interface allows you to test all API endpoints directly.

## API Endpoints (Swagger)

Once the API is running, you can access the Swagger UI at `https://localhost:7086/swagger` (replace port if different).
## How It Works

This application follows a client-server architecture.

### Authentication Flow

1.  **User Registration:** New users can register by providing a username, email, and password. This data is sent to the backend's `/api/Auth/register` endpoint. The backend creates a new user in the database.
2.  **User Login:** Registered users can log in by providing their username and password to the `/api/Auth/login` endpoint.
3.  **JWT Issuance:** Upon successful login, the backend generates a JWT (JSON Web Token) and sends it back to the frontend.
4.  **Token Storage:** The frontend stores this token in the browser's `localStorage`.
5.  **Authorized Requests:** For all subsequent requests to protected API endpoints (e.g., getting books, adding borrowers), the frontend includes this JWT in the `Authorization` header as a `Bearer` token.
6.  **Backend Validation:** The backend validates the received token to ensure the request is from an authenticated and authorized user.

### Library Management Operations

Once logged in, the application presents a dashboard with three main tabs: Books, Borrowers, and Loans.

* **Books:**
    * Users can view a list of all books.
    * **Add Book:** A form allows adding new books with details like Title, Author, ISBN, Publication Year, Genre, and Availability. The ISBN must be between 10 and 13 characters for validation.
    * **Edit Book:** Existing book details can be updated.
    * **Delete Book:** Books can be removed from the system.
    * (Note: Two default books are automatically added to the database on the first load of the Books tab if they don't already exist).
* **Borrowers:**
    * Users can view a list of all registered borrowers.
    * **Add Borrower:** A form allows adding new borrowers with Name and Contact Info (Email).
    * **Edit Borrower:** Existing borrower details can be updated.
    * **Delete Borrower:** Borrowers can be removed.
* **Loans:**
    * Users can view all loan records (active and returned).
    * **Borrow Book:** A form allows creating a new loan by selecting an available book and an existing borrower.
    * **Return Book:** Active loans can be marked as returned.
    * **Delete Loan:** Loan records can be deleted.
 
    * for better illustration i have attached multiple screenshots of the working project in the images folder
  ## Features

* **User Authentication:** Secure registration and login for library staff.
* **Book Management (CRUD):** Add, view, edit, and delete book records.
* **Borrower Management (CRUD):** Add, view, edit, and delete borrower records.
* **Loan Management (CRUD):** Record new loans (borrowing a book), mark books as returned, and delete loan records.
* **Availability Tracking:** Books are marked as available/unavailable based on loan status.
* **Responsive UI:** A clean and modern user interface built with React.js.

## Technologies Used

### Backend

* **ASP.NET Core Web API:** For building robust and scalable APIs.
* **C#:** The primary programming language.
* **Entity Framework Core:** ORM for database interaction (Code-First approach).
* **SQL Server:** Relational database to store library data.
* **JWT (JSON Web Tokens):** For secure user authentication and authorization.

### Frontend

* **React.js:** A JavaScript library for building user interfaces.
* **HTML5/CSS3:** For structuring and styling the web pages.
* **JavaScript (ES6+):** Programming language for frontend logic.
* **Fetch API:** For making HTTP requests to the backend API.
