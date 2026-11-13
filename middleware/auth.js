const jwt = require('jsonwebtoken');

// Verify Admin Token
const verifyAdminToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token missing' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err || decoded.role !== 'admin') {
      return res.status(403).json({ error: 'Access denied: Admin authorization required' });
    }
    req.admin = decoded;
    next();
  });
};

// Verify Teacher Token
const verifyTeacherToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token missing' });
  }

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err || decoded.role !== 'teacher') {
      return res.status(403).json({ error: 'Access denied: Teacher authorization required' });
    }
    req.teacher = decoded;
    next();
  });
};

// -------------------------------------------------------------
// Verify ESP32 Device API Key
// -------------------------------------------------------------
const verifyDeviceApiKey = (req, res, next) => {
  const apiKey = req.headers['x-api-key'];

  if (!apiKey) {
    return res.status(401).json({
      error: 'Device API key missing'
    });
  }

  // Compare with the API key stored in .env
  if (apiKey !== process.env.DEVICE_API_KEY) {
    return res.status(403).json({
      error: 'Invalid device API key'
    });
  }

  next();
};

module.exports = {
  verifyAdminToken,
  verifyTeacherToken,
  verifyDeviceApiKey
};