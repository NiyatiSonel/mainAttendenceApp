const db = require('./db');
const bcrypt = require('bcryptjs');

const seedAdmin = () => {
  const existing = db.prepare('SELECT * FROM ADMIN LIMIT 1').get();
  if (!existing) {
    const email = 'admin@attendance.com';
    const rawPass = 'Niyati@12345';
    const hash = bcrypt.hashSync(rawPass, 10);

    db.prepare(`
      INSERT INTO ADMIN (name, email, pass_hash)
      VALUES (?, ?, ?)
    `).run('System Administrator', email, hash);

    console.log('Admin account created with pass_hash.');
  } else {
    console.log('Admin already exists.');
  }
};

seedAdmin();