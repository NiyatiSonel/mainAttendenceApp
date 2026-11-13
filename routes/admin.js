require('dotenv').config();
const express = require('express');
const router = express.Router();
const db = require('../db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const {
  verifyAdminToken,
  verifyDeviceApiKey
} = require('../middleware/auth');
//------------------------------------------------------------
// SUPER ADMIN CONFIGURATION
//------------------------------------------------------------
const SUPER_ADMIN = {
  id: Number(process.env.SUPER_ADMIN_ID),
  name: process.env.SUPER_ADMIN_NAME,
  email: process.env.SUPER_ADMIN_EMAIL,
  password: process.env.SUPER_ADMIN_PASSWORD,
  is_super: true
};

// -------------------------------------------------------------
// 10. GET PENDING ENROLLMENT COMMAND FOR ESP32
// -------------------------------------------------------------
router.get('/pending-enrollment', verifyDeviceApiKey, (req, res)  => {
  try {
    // No enrollment request waiting
    if (!pendingEnrollmentCommand) {
      return res.json({
        enroll: false
      });
    }

    // Send the pending request to ESP32
    const command = pendingEnrollmentCommand;

    // Clear it so the same enrollment is not processed again
    pendingEnrollmentCommand = null;

    console.log(
      `Sending enrollment request to ESP32 for student ID #${command.studentId}`
    );

    res.json({
      enroll: true,
      studentId: command.studentId,
      rollNo: command.rollNo
    });

  } catch (err) {
    console.error('Pending enrollment error:', err.message);
    res.status(500).json({
      error: err.message
    });
  }
});

// -------------------------------------------------------------
// ESP32 - RECEIVE FINGERPRINT TEMPLATE
// -------------------------------------------------------------
// This endpoint receives the extracted fingerprint template
// from the ESP32 and saves it against the student's ID.
//
// Authentication:
// ESP32 uses x-api-key (DEVICE_API_KEY)
// -------------------------------------------------------------
router.post(
  '/biometrics/upload',
  verifyDeviceApiKey,
  (req, res) => {

    const { studentId, biometric_template } = req.body;

    // Validate student ID
    if (!studentId) {
      return res.status(400).json({
        error: 'Student ID is required'
      });
    }

    // Validate template
    if (!biometric_template) {
      return res.status(400).json({
        error: 'Fingerprint template is required'
      });
    }

    try {

      // Check that student exists
      const student = db
        .prepare(
          'SELECT stu_ID, roll_no, name FROM STUDENTS WHERE stu_ID = ?'
        )
        .get(studentId);

      if (!student) {
        return res.status(404).json({
          error: 'Student not found'
        });
      }

      // Save fingerprint template
      const result = db
        .prepare(
          'UPDATE STUDENTS SET biometric_temp = ? WHERE stu_ID = ?'
        )
        .run(
          biometric_template,
          studentId
        );

      if (result.changes === 0) {
        return res.status(500).json({
          error: 'Fingerprint template was not saved'
        });
      }

      console.log(
        `Fingerprint template saved for student ID #${studentId}`
      );

      console.log(
        `Template size received: ${biometric_template.length} characters`
      );

      return res.json({
        success: true,
        message: 'Fingerprint template saved successfully',
        studentId: studentId
      });

    } catch (err) {

      console.error(
        'Fingerprint template upload error:',
        err.message
      );

      return res.status(500).json({
        error: err.message
      });
    }
  }
);

// -------------------------------------------------------------
// 1. ADMIN LOGIN
// -------------------------------------------------------------
router.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  // 1. Check Super Admin
  if (email.toLowerCase() === SUPER_ADMIN.email.toLowerCase()) {
    if (password === SUPER_ADMIN.password) {
      const token = jwt.sign(
        {
          id: SUPER_ADMIN.id,
          role: 'admin',
          isSuper: true
        },
        process.env.JWT_SECRET,
        { expiresIn: '8h' }
      );

      return res.json({
        message: 'Super Admin login successful',
        token,
        admin: {
          id: SUPER_ADMIN.id,
          name: SUPER_ADMIN.name,
          email: SUPER_ADMIN.email,
          isSuper: true
        }
      });
    } else {
      return res.status(401).json({
        error: 'Invalid admin credentials'
      });
    }
  }

  // 2. Check database for normal admins
  try {
    const admin = db.prepare(
      'SELECT admin_ID, name, email, pass_hash FROM ADMIN WHERE LOWER(email) = LOWER(?)'
    ).get(email);

    if (!admin) {
      return res.status(401).json({
        error: 'Invalid admin credentials'
      });
    }

    const isMatch = bcrypt.compareSync(password, admin.pass_hash);

    if (!isMatch) {
      return res.status(401).json({
        error: 'Invalid admin credentials'
      });
    }

    const token = jwt.sign(
      {
        id: admin.admin_ID,
        role: 'admin',
        isSuper: false
      },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    return res.json({
      message: 'Admin login successful',
      token,
      admin: {
        id: admin.admin_ID,
        name: admin.name,
        email: admin.email,
        isSuper: false
      }
    });

  } catch (err) {
    console.error('Admin login error:', err.message);

    return res.status(500).json({
      error: err.message
    });
  }
});

// -------------------------------------------------------------
// ESP32 - PENDING ATTENDANCE SESSION
// -------------------------------------------------------------

let pendingAttendanceCommand = null;

router.get('/pending-attendance', verifyDeviceApiKey, (req, res) => {
  try {
    const session = db.prepare(`
      SELECT
        session_ID,
        sub_ID,
        device_ID
      FROM SESSIONS
      WHERE status = 1
        AND datetime('now', 'localtime') >= datetime(start_time)
        AND datetime('now', 'localtime') <= datetime(end_time)
      ORDER BY session_ID DESC
      LIMIT 1
    `).get();

    if (!session) {
      return res.json({
        attendance: false
      });
    }

    res.json({
      attendance: true,
      sessionId: session.session_ID,
      subjectId: session.sub_ID,
      deviceId: session.device_ID
    });

  } catch (err) {
    console.error('Pending attendance error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// ESP32 - GET FINGERPRINT TEMPLATES FOR ACTIVE ATTENDANCE SESSION
// -------------------------------------------------------------

router.get('/attendance-templates', verifyDeviceApiKey, (req, res) => {
  try {
    const sessionId = parseInt(req.query.sessionId, 10);

    if (!sessionId) {
      return res.status(400).json({
        error: 'Session ID is required'
      });
    }

    // ---------------------------------------------------------
    // Check that the session is currently active by time
    // ---------------------------------------------------------

    const session = db.prepare(`
      SELECT
        session_ID,
        sub_ID,
        device_ID
      FROM SESSIONS
      WHERE session_ID = ?
        AND status = 1
        AND datetime('now', 'localtime') >= datetime(start_time)
        AND datetime('now', 'localtime') <= datetime(end_time)
    `).get(sessionId);

    if (!session) {
      return res.status(404).json({
        error: 'Active attendance session not found'
      });
    }

    // ---------------------------------------------------------
    // Get students enrolled in this subject
    // who have a fingerprint template
    // ---------------------------------------------------------

    const students = db.prepare(`
      SELECT
        s.stu_ID AS studentId,
        s.roll_no AS rollNo,
        s.name,
        s.biometric_temp AS template
      FROM ENROLLMENTS e
      JOIN STUDENTS s
        ON e.stu_ID = s.stu_ID
      WHERE e.sub_ID = ?
        AND s.biometric_temp IS NOT NULL
        AND s.biometric_temp != ''
        AND s.biometric_temp != 'PENDING_ENROLLMENT'
      ORDER BY s.roll_no ASC
    `).all(session.sub_ID);

    res.json({
      success: true,
      sessionId: session.session_ID,
      subjectId: session.sub_ID,
      deviceId: session.device_ID,
      students
    });

  } catch (err) {
    console.error('Attendance templates error:', err.message);
    res.status(500).json({
      error: err.message
    });
  }
});

// Protect all following admin routes
router.use(verifyAdminToken);

// -------------------------------------------------------------
// 2. DASHBOARD METRICS
// -------------------------------------------------------------
router.get('/stats', (req, res) => {
  try {
    const totalStudents = db.prepare('SELECT COUNT(*) as count FROM STUDENTS').get()?.count || 0;
    const totalTeachers = db.prepare('SELECT COUNT(*) as count FROM TEACHER').get()?.count || 0;
    const totalSubjects = db.prepare('SELECT COUNT(*) as count FROM SUBJECT').get()?.count || 0;
    const totalDevices = db.prepare('SELECT COUNT(*) as count FROM DEVICES').get()?.count || 0;
    res.json({ totalStudents, totalTeachers, totalSubjects, totalDevices });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 3. TEACHER CRUD
// -------------------------------------------------------------
router.get('/teachers', (req, res) => {
  try {
    const teachers = db.prepare('SELECT teacher_ID as id, name, email FROM TEACHER').all();
    res.json(teachers);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/teachers', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email, and password required' });
  }

  try {
    const hash = bcrypt.hashSync(password, 10);
    const result = db.prepare(`
      INSERT INTO TEACHER (name, email, pass_hash) 
      VALUES (?, ?, ?)
    `).run(name, email, hash);

    res.status(201).json({ message: 'Teacher added successfully', id: result.lastInsertRowid });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/teachers/:id', (req, res) => {
  const teacherId = parseInt(req.params.id, 10);
  try {
    // Unlink teacher from assigned subjects first
    db.prepare('UPDATE SUBJECT SET teacher_ID = NULL WHERE teacher_ID = ?').run(teacherId);
    // Delete the teacher
    db.prepare('DELETE FROM TEACHER WHERE teacher_ID = ?').run(teacherId);
    res.json({ message: 'Teacher deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 4. SUBJECT CRUD & TEACHER ASSIGNMENT
// -------------------------------------------------------------
router.get('/subjects', (req, res) => {
  try {
    const subjects = db.prepare(`
      SELECT 
        s.sub_ID as id,
        s.subject_name,
        s.teacher_ID as teacher_id,
        t.name as teacher_name,
        s.semester_ID as semester_id,
        sem.semester_name
      FROM SUBJECT s
      LEFT JOIN TEACHER t
        ON s.teacher_ID = t.teacher_ID
      LEFT JOIN SEMESTERS sem
        ON s.semester_ID = sem.semester_ID
      ORDER BY s.sub_ID ASC
    `).all();

    res.json(subjects.map(s => ({
      ...s,
      teacher_name: s.teacher_name || 'Unassigned',
      semester_name: s.semester_name || 'Unassigned'
    })));

  } catch (err) {
    console.error('Fetch subjects error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

router.post('/subjects', (req, res) => {
  const {
    subject_name,
    teacher_id,
    semester_id
  } = req.body;

  if (!subject_name) {
    return res.status(400).json({
      error: 'Subject name is required'
    });
  }

  const parsedTeacherId =
    teacher_id && String(teacher_id).trim() !== ''
      ? parseInt(teacher_id, 10)
      : null;

  const parsedSemesterId =
    semester_id && String(semester_id).trim() !== ''
      ? parseInt(semester_id, 10)
      : null;

  try {
    const result = db.prepare(`
      INSERT INTO SUBJECT (
        subject_name,
        teacher_ID,
        semester_ID
      )
      VALUES (?, ?, ?)
    `).run(
      subject_name.trim(),
      parsedTeacherId,
      parsedSemesterId
    );

    res.status(201).json({
      message: 'Subject created successfully',
      id: result.lastInsertRowid
    });

  } catch (err) {
    console.error('Create subject error:', err.message);

    res.status(400).json({
      error: err.message
    });
  }
});

router.put('/subjects/:id', (req, res) => {
  const subId = parseInt(req.params.id, 10);
  const { teacher_id } = req.body;

  const parsedTeacherId = teacher_id && String(teacher_id).trim() !== '' 
    ? parseInt(teacher_id, 10) 
    : null;

  try {
    db.prepare('UPDATE SUBJECT SET teacher_ID = ? WHERE sub_ID = ?').run(parsedTeacherId, subId);
    res.json({ message: 'Subject assignment updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// GET ACTIVE SEMESTERS
// -------------------------------------------------------------
router.get('/semesters', (req, res) => {
  try {
    const semesters = db.prepare(`
      SELECT
        semester_ID AS id,
        semester_name,
        start_date,
        end_date,
        status
      FROM SEMESTERS
      WHERE status = 1
      ORDER BY start_date DESC
    `).all();

    res.json(semesters);

  } catch (err) {
    console.error('Fetch semesters error:', err.message);
    res.status(500).json({
      error: err.message
    });
  }
});

// -------------------------------------------------------------
// CREATE SEMESTER
// -------------------------------------------------------------
router.post('/semesters', (req, res) => {
  const {
    semester_name,
    start_date,
    end_date
  } = req.body;

  if (!semester_name || !start_date || !end_date) {
    return res.status(400).json({
      error: 'Semester name, start date, and end date are required'
    });
  }

  if (new Date(start_date) >= new Date(end_date)) {
    return res.status(400).json({
      error: 'End date must be after start date'
    });
  }

  try {
    const result = db.prepare(`
      INSERT INTO SEMESTERS (
        semester_name,
        start_date,
        end_date,
        status
      )
      VALUES (?, ?, ?, 1)
    `).run(
      semester_name.trim(),
      start_date,
      end_date
    );

    res.status(201).json({
      message: 'Semester created successfully',
      id: result.lastInsertRowid
    });

  } catch (err) {
    console.error('Create semester error:', err.message);

    res.status(400).json({
      error: err.message
    });
  }
});

// -------------------------------------------------------------
// 5. STUDENTS & BIOMETRIC_TEMP ENROLLMENT
// -------------------------------------------------------------
router.get('/students', (req, res) => {
  try {
    const students = db.prepare(`
      SELECT 
        stu_ID as id, 
        roll_no,
        name, 
        CASE 
          WHEN biometric_temp IS NOT NULL 
               AND biometric_temp != 'PENDING_ENROLLMENT' 
               AND LENGTH(biometric_temp) > 0 
          THEN 1 ELSE 0 
        END as has_fingerprint 
      FROM STUDENTS
      ORDER BY stu_ID ASC
    `).all();
    res.json(students);
  } catch (err) {
    console.error('Fetch students error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

router.post('/students', (req, res) => {
  const { roll_no, name, biometric_template } = req.body;

  if (!name || !roll_no) {
    return res.status(400).json({ error: 'Both Roll Number and Student Name are required' });
  }

  const templatePayload = biometric_template && biometric_template.trim() !== '' 
    ? biometric_template 
    : 'PENDING_ENROLLMENT';

  try {
    const result = db.prepare(`
      INSERT INTO STUDENTS (roll_no, name, biometric_temp) 
      VALUES (?, ?, ?)
    `).run(roll_no.trim(), name.trim(), templatePayload);

    res.status(201).json({ 
      message: 'Student registered successfully', 
      id: result.lastInsertRowid 
    });
  } catch (err) {
    console.error('Register student error:', err.message);
    res.status(400).json({ error: err.message });
  }
});

router.put('/students/:id/biometrics', (req, res) => {
  const stuId = parseInt(req.params.id, 10);
  const { biometric_template } = req.body;

  if (!biometric_template) {
    return res.status(400).json({ error: 'Biometric template data is required' });
  }

  try {
    db.prepare('UPDATE STUDENTS SET biometric_temp = ? WHERE stu_ID = ?').run(biometric_template, stuId);
    res.json({ message: 'Fingerprint enrolled successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 6. ENROLLMENTS (STUDENT-SUBJECT JUNCTION)
// -------------------------------------------------------------
router.get('/enrollments', (req, res) => {
  try {
    const enrollments = db.prepare(`
      SELECT 
        e.enroll_ID as id,
        e.stu_ID as student_id,
        st.roll_no,
        st.name as student_name,
        e.sub_ID as subject_id,
        sub.subject_name
      FROM ENROLLMENTS e
      LEFT JOIN STUDENTS st ON e.stu_ID = st.stu_ID
      LEFT JOIN SUBJECT sub ON e.sub_ID = sub.sub_ID
      ORDER BY e.enroll_ID DESC
    `).all();

    res.json(enrollments);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/enrollments', (req, res) => {
  const { student_id, subject_id } = req.body;
  if (!student_id || !subject_id) {
    return res.status(400).json({ error: 'Select both a student and a subject' });
  }

  try {
    const result = db.prepare(`
      INSERT INTO ENROLLMENTS (stu_ID, sub_ID) 
      VALUES (?, ?)
    `).run(parseInt(student_id, 10), parseInt(subject_id, 10));

    res.status(201).json({ message: 'Student enrolled successfully', id: result.lastInsertRowid });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/enrollments/:id', (req, res) => {
  const enrollId = parseInt(req.params.id, 10);
  try {
    db.prepare('DELETE FROM ENROLLMENTS WHERE enroll_ID = ?').run(enrollId);
    res.json({ message: 'Enrollment removed successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 7. DEVICES (ESP32)
// -------------------------------------------------------------
router.get('/devices', (req, res) => {
  try {
    const devices = db.prepare(`
      SELECT 
        device_ID as id, 
        mac_address, 
        auth_token, 
        status 
      FROM DEVICES
    `).all();
    res.json(devices);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/devices', (req, res) => {
  const { mac_address, auth_token, status } = req.body;
  if (!mac_address) {
    return res.status(400).json({ error: 'MAC address is required' });
  }

  const deviceStatus = status !== undefined && status !== '' ? parseInt(status, 10) : 1; // 1 = Active
  const token = auth_token || `TOKEN_${Date.now()}`;

  try {
    const result = db.prepare(`
      INSERT INTO DEVICES (mac_address, auth_token, status) 
      VALUES (?, ?, ?)
    `).run(mac_address, token, deviceStatus);

    res.status(201).json({ message: 'Device registered successfully', id: result.lastInsertRowid });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 8. ADMIN MANAGEMENT (ADD / LIST / DELETE OTHER ADMINS)
// -------------------------------------------------------------

// Get all admins (exclude password hashes)
router.get('/admins', (req, res) => {
  try {
    // 1. Get any other sub-admins from DB (if any)
    let dbAdmins = [];
    try {
      dbAdmins = db.prepare(
        'SELECT admin_ID, name, email FROM ADMIN WHERE LOWER(email) != LOWER(?)'
      ).all(SUPER_ADMIN.email);
    } catch (e) {
      // If ADMIN table is dropped or empty, dbAdmins remains []
      dbAdmins = [];
    }

    const formattedDbAdmins = dbAdmins.map((a) => ({
      id: a.admin_ID,
      name: a.name,
      email: a.email,
      isSuper: false
    }));

    // 2. Put Super Admin permanently at top (ID 1)
    const allAdmins = [
      {
        id: SUPER_ADMIN.id,
        name: SUPER_ADMIN.name,
        email: SUPER_ADMIN.email,
        isSuper: true
      },
      ...formattedDbAdmins
    ];

    res.json(allAdmins);
  } catch (err) {
    console.error('Fetch admins error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Add a new admin
router.post('/admins', (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email, and password are required' });
  }

  try {
    const hash = bcrypt.hashSync(password, 10);
    const result = db.prepare(`
      INSERT INTO ADMIN (name, email, pass_hash) 
      VALUES (?, ?, ?)
    `).run(name, email, hash);

    res.status(201).json({ message: 'Admin added successfully', id: result.lastInsertRowid });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Delete an admin (with self-deletion check)
router.delete('/admins/:id', (req, res) => {
  const targetId = parseInt(req.params.id, 10);

  // Prevent a normal admin from deleting their own account
  if (!req.admin.isSuper && req.admin.id === targetId) {
    return res.status(400).json({
      error: 'You cannot delete your own active administrator account.'
    });
  }

  try {
    const result = db
      .prepare('DELETE FROM ADMIN WHERE admin_ID = ?')
      .run(targetId);

    if (result.changes === 0) {
      return res.status(404).json({
        error: 'Admin account not found in database.'
      });
    }

    res.json({
      message: 'Administrator account deleted successfully.'
    });

  } catch (err) {
    res.status(500).json({
      error: err.message
    });
  }
});

// -------------------------------------------------------------
// 9. TRIGGER FINGERPRINT ENROLLMENT (BRIDGE)
// -------------------------------------------------------------

// In-memory holder for the pending hardware command (or store in a lightweight DB table)
let pendingEnrollmentCommand = null;

router.post('/students/:id/trigger-enroll', (req, res) => {
  const stuId = parseInt(req.params.id, 10);
  const { roll_no } = req.body;

  try {
    const student = db
      .prepare('SELECT * FROM STUDENTS WHERE stu_ID = ?')
      .get(stuId);

    if (!student) {
      return res.status(404).json({ error: 'Student not found' });
    }

    // Create a pending enrollment request for the ESP32
    pendingEnrollmentCommand = {
      action: 'enroll',
      studentId: stuId,
      rollNo: roll_no || student.roll_no,
      timestamp: Date.now()
    };

    console.log(
      `Enrollment request created for student ID #${stuId}`
    );

    res.json({
      message: `Enrollment request created for student ID #${stuId}.`
    });

  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// Endpoint for ESP32 or a bridge helper to check if there's a pending enrollment job
router.get('/hardware/pending-command', (req, res) => {
  // Clear command after it's fetched once so it doesn't loop forever
  const cmd = pendingEnrollmentCommand;
  pendingEnrollmentCommand = null; 
  res.json(cmd || { action: 'none' });
});


module.exports = router;