const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'smartAttend.db')); // or smartAttend_2.db

console.log(
  'ATTENDANCE schema:',
  db.prepare("PRAGMA table_info('ATTENDANCE')").all()
);

// --- AUTOMATIC SCHEMA MIGRATION ---
const studentCols = db.prepare("PRAGMA table_info('STUDENTS')").all().map(c => c.name);

if (!studentCols.includes('roll_no')) {
  db.prepare("ALTER TABLE STUDENTS ADD COLUMN roll_no TEXT").run();
  console.log("Migration Successful: Added 'roll_no' column to STUDENTS table.");
}

module.exports = db;