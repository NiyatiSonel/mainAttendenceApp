
//require('dotenv').config();
const path = require('path');
const fs = require('fs');
const dotenv = require('dotenv');

const envPath = path.join(__dirname, '.env');

console.log('Looking for .env at:', envPath);
console.log('.env exists:', fs.existsSync(envPath));

const result = dotenv.config({ path: envPath });

console.log('dotenv result:', result.error ? result.error.message : 'Loaded');
console.log('JWT SECRET EXISTS:', !!process.env.JWT_SECRET);

const express = require('express');
const cors = require('cors');

//----------------
console.log('ENV FILE:', path.join(__dirname, '.env'));
console.log('JWT SECRET LOADED:', !!process.env.JWT_SECRET);
//-----------------


const adminRoutes = require('./routes/admin');
const attendanceRoutes = require('./routes/attendance');

const app = express();

// Middlewares
app.use(cors({
  origin: '*', // Adjust this to your frontend's URL
}));
app.use(express.json());

// Health route
app.get('/api/health', (req, res) => {
  res.json({ status: 'running', timestamp: new Date().toISOString() });
});

// Mount Admin Routes
app.use('/api/admin', adminRoutes);
app.use('/api/attendance', attendanceRoutes);

const PORT = process.env.PORT || 5000;

// Backend Health/status route
app.get('/', (req, res) => {
    res.json({
        status: 'running',
        timestamp: new Date().toISOString()
    });
});

// Start the server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Central Server listening on port ${PORT}`);
  console.log(`Network API: http://10.63.14.66:${PORT}`);
});

// Add with your existing route imports
const teacherRoutes = require('./routes/teacher');

// Mount under /api/teacher
app.use('/api/teacher', teacherRoutes);

module.exports = app;