require('dotenv').config();
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const prisma = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());

// Helper function to generate JWT
function generateToken(user) {
  const jti = crypto.randomUUID();
  return jwt.sign(
    {
      id: user.id,
      email: user.email
    },
    process.env.JWTSECRET,
    {
      jwtid: jti,
      expiresIn: '1h'
    }
  );
}

// 1. User Registration - POST /signup
app.post('/signup', async (req, res) => {
  try {
    const { email, password, name } = req.body;

    // Check if email and password are provided as strings
    if (!email || !password || typeof email !== 'string' || typeof password !== 'string') {
      return res.status(400).json({ message: 'Email and password are required and must be strings' });
    }

    // Ensure password contains at least 6 characters
    if (password.length < 6) {
      return res.status(400).json({ message: 'Password must be at least 6 characters long' });
    }

    // Normalize email (trim spaces and convert to lowercase)
    const normalizedEmail = email.trim().toLowerCase();

    // Check if user already exists
    const existingUser = await prisma.user.findUnique({
      where: { email: normalizedEmail }
    });

    if (existingUser) {
      return res.status(409).json({ message: 'Email is already registered' });
    }

    // Hash password with bcrypt (10 salt rounds)
    const hashedPassword = await bcrypt.hash(password, 10);

    // Create user in database
    const newUser = await prisma.user.create({
      data: {
        email: normalizedEmail,
        password: hashedPassword,
        name: name ? String(name).trim() : null
      }
    });

    // Generate JWT
    const token = generateToken(newUser);

    // Return user details and JWT
    return res.status(201).json({
      message: 'Registration successful',
      user: {
        id: newUser.id,
        email: newUser.email,
        name: newUser.name,
        createdAt: newUser.createdAt
      },
      token
    });
  } catch (error) {
    console.error('Signup error:', error);
    return res.status(500).json({ message: 'Internal server error' });
  }
});

app.listen(PORT, () => {
  console.log(`Server started on port ${PORT}`);
});
