const jwt = require('jsonwebtoken');

function requireAuth(req, res, next) {
  // Read token from Authorization request header
  const authHeader = req.headers.authorization;

  // Header format should be: Bearer <token>
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ message: 'Unauthorized: Missing or invalid token format' });
  }

  const token = authHeader.split(' ')[1];

  try {
    // Verify token using secret stored in environment variables
    const decoded = jwt.verify(token, process.env.JWTSECRET);
    // Attach decoded payload to req.user
    req.user = decoded;
    next();
  } catch (error) {
    return res.status(401).json({ message: 'Unauthorized: Invalid or expired token' });
  }
}

module.exports = requireAuth;
