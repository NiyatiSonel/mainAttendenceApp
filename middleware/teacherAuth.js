const jwt = require('jsonwebtoken');

const verifyTeacherToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];

  if (!authHeader) {
    return res.status(401).json({
      error: 'Access denied. No token provided.'
    });
  }

  const token = authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({
      error: 'Malformed token.'
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    if (decoded.role !== 'teacher') {
      return res.status(403).json({
        error: 'Forbidden. Teacher role required.'
      });
    }

    req.teacher = decoded;

    next();

  } catch (err) {
    return res.status(401).json({
      error: 'Invalid or expired token.'
    });
  }
};

module.exports = {
  verifyTeacherToken
};