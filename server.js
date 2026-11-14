const path = require('path');
const fs = require('fs');
const dotenv = require('dotenv');

const envPath = path.join(__dirname, '.env');
dotenv.config({ path: envPath });

console.log('JWT SECRET EXISTS:', !!process.env.JWT_SECRET);
console.log('SUPABASE URL EXISTS:', !!process.env.SUPABASE_URL);

const express = require('express');
const cors = require('cors');

const adminRoutes = require('./routes/admin');
const attendanceRoutes = require('./routes/attendance');
const teacherRoutes = require('./routes/teacher');

const app = express();

// Middlewares
app.use(cors({
  origin: '*',
}));
app.use(express.json());

// Health route
app.get('/api/health', (req, res) => {
  res.json({ status: 'running', timestamp: new Date().toISOString() });
});

// Root route
app.get('/', (req, res) => {
  res.json({
    status: 'running',
    timestamp: new Date().toISOString()
  });
});

// Mount Routes
app.use('/api/admin', adminRoutes);
app.use('/api/attendance', attendanceRoutes);
app.use('/api/teacher', teacherRoutes);

const PORT = process.env.PORT || 5000;

// Start server locally (Vercel invokes the exported app handler)
if (!process.env.VERCEL) {
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Central Server listening on port ${PORT}`);
  });
}

module.exports = app;
