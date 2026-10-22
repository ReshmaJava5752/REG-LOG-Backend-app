# REG-LOG BACKEND
Backend application for the Registration and Login System.

Technologies Used

- Java
- Spring Boot 3.4
- Maven
- MySQL
- JWT Authentication

Features

- User registration and login
- Password validation
- Email OTP verification
- JWT-based authentication
- Protected API endpoints
- Password reset functionality

Running the Project

1. Install JDK and MySQL.
2. Configure database and email settings in your local application configuration.
3. Open a terminal in the backend project folder.
4. Run the application using Maven:

mvn spring-boot:run

The backend is configured to run locally on port "8080".

Security

Never upload passwords, email credentials, JWT secrets, or database credentials to GitHub. Keep sensitive values in local configuration or environment variables.

Project Structure

- "src/" — Application source code
- "pom.xml" — Maven dependencies and build configuration
- ".env.example" — Example environment configuration
