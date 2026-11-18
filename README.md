# User Authentication System Using JWT

A simple and clean JWT authentication backend built with Node.js, Express, Prisma, and PostgreSQL.

## Features
- **User Registration (`POST /signup`)**: Password hashing with bcrypt, input validation, normalized emails.
- **User Login (`POST /login`)**: Secure credential check and JWT issuance.
- **Auth Middleware (`requireAuth`)**: Bearer token parsing and secret verification.
- **Protected Profile (`GET /me`)**: Returns user profile without exposing sensitive information.
- **Protected Dashboard (`GET /dashboard`)**: Greets user by name or email.

## Setup Instructions

1. Install dependencies:
   ```bash
   npm install
   ```

2. Configure environment variables:
   Copy `.env.example` to `.env` and fill in your PostgreSQL database credentials and JWT secret:
   ```bash
   cp .env.example .env
   ```

3. Run Prisma migrations:
   ```bash
   npx prisma migrate dev --name init
   ```

4. Start the server:
   ```bash
   npm start
   ```
