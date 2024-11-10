/* SQL injection prevention:
- Input Validation and Sanitization: Ensure inputs are safe to prevent issues like injection attacks.
- Rate Limiting and Protection: Your current brute force middleware is good, but we’ll ensure it works effectively to prevent abuse.
- Error Handling: Avoid leaking any sensitive information in the error messages.
- JWT Security: Ensure your JWT tokens are signed securely and have an expiration
*/
import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import Admin from '../models/admin.js';
import bruteForce from '../middleware/bruteforceprotectionmiddleware.js';
import { body, validationResult } from 'express-validator';
import xss from 'xss-clean';

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET;

// Middleware to validate and sanitize inputs
const validateLogin = [
  body('username')
    .trim()
    .escape() // Escape characters to avoid XSS
    .isLength({ min: 5 }).withMessage('Username must be at least 5 characters'),
  body('password')
    .trim()
    .escape() // Escape characters to avoid XSS
    .isLength({ min: 6 }).withMessage('Password must be at least 6 characters'),
];

// Apply xss-clean to sanitize all incoming inputs at the router level
router.use(xss());

// POST /login route for admin
router.post('/login', bruteForce.prevent, validateLogin, async (req, res) => {
  // Check for validation errors
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, password } = req.body;

  try {
    // Find the admin by username
    const admin = await Admin.findOne({ username });

    if (!admin) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Compare passwords securely
    const isPasswordValid = await bcrypt.compare(password, admin.password);
    if (!isPasswordValid) {
      return res.status(400).json({ message: 'Invalid credentials' });
    }

    // Create JWT token with expiration and secure signing
    const token = jwt.sign(
      { id: admin._id, role: 'admin' },
      JWT_SECRET,
      { expiresIn: '1h' } // Token expires in 1 hour
    );

    res.json({ message: 'Login successful', token });

  } catch (error) {
    console.error('Error logging in admin:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

export default router;
