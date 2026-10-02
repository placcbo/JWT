# Blog API — JWT Authentication

A RESTful Blog API built with Go, Chi, bcrypt, and JWT authentication.

This project extends a Go Blog API with user authentication and authorization. Users can create accounts, securely store passwords using bcrypt, log in to receive JWT tokens, and access protected routes.

The API also implements ownership checks so users can only update or delete their own posts.

---

## Features

- User signup
- Secure password hashing with bcrypt
- User login
- JWT token generation
- JWT authentication middleware
- Protected routes
- Post ownership checks
- Authentication vs authorization handling
- `401 Unauthorized` and `403 Forbidden` responses
- RESTful API structure
- JSON request and response handling
- Chi HTTP router

---

## Tech Stack

- **Go**
- **Chi Router**
- **JWT**
- **bcrypt**
- **REST API**
- **JSON**
- **PostgreSQL** *(planned/integration layer)*
- **Thunder Client** for API testing

---

## Authentication Flow

```text
Signup
   ↓
Password
   ↓
bcrypt hashing
   ↓
Store user
   ↓
Login
   ↓
Check password
   ↓
Generate JWT
   ↓
Client receives token
   ↓
Bearer token
   ↓
Authentication middleware
   ↓
Extract user ID
   ↓
Protected route
