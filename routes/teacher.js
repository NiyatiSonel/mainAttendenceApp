const express = require('express');
const router = express.Router();
const db = require('../db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { verifyTeacherToken } = require('../middleware/teacherAuth');

// -------------------------------------------------------------
// 1. TEACHER LOGIN
// -------------------------------------------------------------
router.post('/login', (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    // Exact schema check: teacher_ID, name, email, pass_hash
    const teacher = db.prepare(`
      SELECT teacher_ID, name, email, pass_hash 
      FROM TEACHER 
      WHERE LOWER(email) = LOWER(?)
    `).get(email);

    if (!teacher) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isMatch = bcrypt.compareSync(password, teacher.pass_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Sign JWT token specifically for teacher role
    const token = jwt.sign(
      { id: teacher.teacher_ID, role: 'teacher' },
      process.env.JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({
      message: 'Login successful',
      token,
      teacher: {
        id: teacher.teacher_ID,
        name: teacher.name,
        email: teacher.email
      }
    });
  } catch (err) {
    console.error('Teacher login error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Protect all subsequent endpoints
router.use(verifyTeacherToken);

// -------------------------------------------------------------
// GET REGISTERED ESP32 DEVICES
// -------------------------------------------------------------
router.get('/devices', (req, res) => {
  try {
    const devices = db.prepare(`
      SELECT
        device_ID as id,
        mac_address,
        status
      FROM DEVICES
      WHERE status = 1
      ORDER BY device_ID ASC
    `).all();

    res.json(devices);
  } catch (err) {
    console.error('Fetch devices error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 2. TEACHER PROFILE & ASSIGNED SUBJECTS
// -------------------------------------------------------------
router.get('/profile', (req, res) => {
  const teacherId = req.teacher.id;

  try {
    // 1. Get teacher personal details
    const teacher = db.prepare(`
      SELECT teacher_ID as id, name, email 
      FROM TEACHER 
      WHERE teacher_ID = ?
    `).get(teacherId);

    if (!teacher) {
      return res.status(404).json({ error: 'Teacher profile not found' });
    }

    // 2. Get subjects assigned to this specific teacher
    const assignedSubjects = db.prepare(`
      SELECT sub_ID as id, subject_name 
      FROM SUBJECT 
      WHERE teacher_ID = ?
    `).all(teacherId);

    res.json({
      profile: teacher,
      subjects: assignedSubjects
    });
  } catch (err) {
    console.error('Teacher profile fetch error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 3. GET ENROLLED STUDENTS FOR A SPECIFIC SUBJECT
// -------------------------------------------------------------
router.get('/subjects/:subId/students', (req, res) => {
  const teacherId = req.teacher.id;
  const subId = parseInt(req.params.subId, 10);

  try {
    const subject = db.prepare(`
      SELECT sub_ID, subject_name 
      FROM SUBJECT 
      WHERE sub_ID = ? AND teacher_ID = ?
    `).get(subId, teacherId);

    if (!subject) {
      return res.status(403).json({ error: 'Subject not found or unauthorized' });
    }

    const students = db.prepare(`
      SELECT 
        s.stu_ID as id, 
        s.roll_no,
        s.name,
        CASE 
          WHEN s.biometric_temp IS NOT NULL AND LENGTH(s.biometric_temp) > 0 
          THEN 1 ELSE 0 
        END as has_fingerprint
      FROM ENROLLMENTS e
      JOIN STUDENTS s ON e.stu_ID = s.stu_ID
      WHERE e.sub_ID = ?
      ORDER BY s.roll_no ASC
    `).all(subId);

    res.json({ subject, students });
  } catch (err) {
    console.error('Teacher enrolled students error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// COMPLETE SUBJECT ATTENDANCE REPORT
// -------------------------------------------------------------
router.get('/subjects/:subId/report', (req, res) => {
  const teacherId = req.teacher.id;
  const subId = parseInt(req.params.subId, 10);

  try {

    // 1. Verify that the subject belongs to this teacher
    const subject = db.prepare(`
      SELECT
        s.sub_ID,
        s.subject_name,
        t.name AS teacher_name,
        sem.semester_name
      FROM SUBJECT s
      LEFT JOIN TEACHER t
        ON s.teacher_ID = t.teacher_ID
      LEFT JOIN SEMESTERS sem
        ON s.semester_ID = sem.semester_ID
      WHERE s.sub_ID = ?
        AND s.teacher_ID = ?
    `).get(subId, teacherId);

    if (!subject) {
      return res.status(403).json({
        error: 'Subject not found or unauthorized'
      });
    }

    // 2. Get all sessions for this subject
    const sessions = db.prepare(`
      SELECT
        session_ID,
        start_time,
        end_time
      FROM SESSIONS
      WHERE teacher_ID = ?
        AND sub_ID = ?
      ORDER BY start_time ASC
    `).all(teacherId, subId);

    // 3. Get all students enrolled in this subject
    const students = db.prepare(`
      SELECT
        s.stu_ID AS student_id,
        s.roll_no,
        s.name
      FROM ENROLLMENTS e
      JOIN STUDENTS s
        ON e.stu_ID = s.stu_ID
      WHERE e.sub_ID = ?
      ORDER BY s.roll_no ASC
    `).all(subId);

    // 4. Get attendance records for this subject
    const attendance = db.prepare(`
      SELECT
        a.session_ID,
        a.stu_ID,
        a.status
      FROM ATTENDANCE a
      JOIN SESSIONS se
        ON a.session_ID = se.session_ID
      WHERE se.teacher_ID = ?
        AND se.sub_ID = ?
    `).all(teacherId, subId);

    // 5. Create attendance lookup
    const attendanceMap = {};

    attendance.forEach((record) => {

      if (!attendanceMap[record.stu_ID]) {
        attendanceMap[record.stu_ID] = {};
      }

      attendanceMap[record.stu_ID][record.session_ID] =
        record.status;
    });

    // 6. Build complete student attendance report
    const reportStudents = students.map((student) => {

      let present = 0;
      let absent = 0;

      const attendance = sessions.map((session) => {

        const status =
          attendanceMap[student.student_id]?.[session.session_ID]
          || 'Absent';

        if (status.toLowerCase() === 'present') {
          present++;
        } else {
          absent++;
        }

        return {
          session_id: session.session_ID,
          date: session.start_time,
          status
        };
      });

      const percentage =
        sessions.length > 0
          ? Number(((present / sessions.length) * 100).toFixed(2))
          : 0;

      return {
        student_id: student.student_id,
        roll_no: student.roll_no,
        name: student.name,
        attendance,
        present,
        absent,
        percentage
      };
    });

    // 7. Send complete report
    res.json({
      subject,
      totalSessions: sessions.length,
      sessions,
      students: reportStudents
    });

  } catch (err) {

    console.error(
      'Complete subject attendance report error:',
      err.message
    );

    res.status(500).json({
      error: err.message
    });
  }
});

// -------------------------------------------------------------
// 4. GET STUDENT ATTENDANCE REPORT FOR A SUBJECT
// -------------------------------------------------------------

router.get('/subjects/:subId/students', (req, res) => {
  const teacherId = req.teacher.id;
  const subId = parseInt(req.params.subId, 10);

  try {
    // Verify subject belongs to this teacher
    const subject = db.prepare(`
      SELECT sub_ID, subject_name
      FROM SUBJECT
      WHERE sub_ID = ? AND teacher_ID = ?
    `).get(subId, teacherId);

    if (!subject) {
      return res.status(403).json({
        error: 'Subject not found or unauthorized'
      });
    }

    // Fetch enrolled students with attendance statistics
    const students = db.prepare(`
      WITH completed_sessions AS (
        SELECT session_ID
        FROM SESSIONS
        WHERE sub_ID = ?
          AND teacher_ID = ?
          AND status = 0
      ),

      session_count AS (
        SELECT COUNT(*) AS total_sessions
        FROM completed_sessions
      ),

      attendance_summary AS (
        SELECT
          a.stu_ID,
          COUNT(DISTINCT a.session_ID) AS attended_sessions
        FROM ATTENDANCE a
        JOIN completed_sessions cs
          ON a.session_ID = cs.session_ID
        WHERE LOWER(TRIM(a.status)) = 'present'
        GROUP BY a.stu_ID
      )

      SELECT
        s.stu_ID AS id,
        s.roll_no,
        s.name,

        CASE
          WHEN s.biometric_temp IS NOT NULL
            AND LENGTH(s.biometric_temp) > 0
          THEN 1
          ELSE 0
        END AS has_fingerprint,

        sc.total_sessions,

        COALESCE(a.attended_sessions, 0)
          AS attended_sessions,

        sc.total_sessions -
          COALESCE(a.attended_sessions, 0)
          AS absent_sessions,

        CASE
          WHEN sc.total_sessions > 0
          THEN ROUND(
            100.0 * COALESCE(a.attended_sessions, 0)
            / sc.total_sessions,
            1
          )
          ELSE 0
        END AS attendance_percentage

      FROM ENROLLMENTS e

      JOIN STUDENTS s
        ON e.stu_ID = s.stu_ID

      CROSS JOIN session_count sc

      LEFT JOIN attendance_summary a
        ON a.stu_ID = s.stu_ID

      WHERE e.sub_ID = ?

      ORDER BY s.roll_no ASC

    `).all(subId, teacherId, subId);

    res.json({
      subject,
      students
    });

  } catch (err) {
    console.error(
      'Teacher enrolled students error:',
      err.message
    );

    res.status(500).json({
      error: err.message
    });
  }
});



// -------------------------------------------------------------
// 5. START AN INSTANT SESSION
// -------------------------------------------------------------
router.post('/sessions/start', (req, res) => {
  const teacherId = req.teacher.id;
  const { device_id, subject_id, start_time, end_time } = req.body;

  if (!device_id) {
    return res.status(400).json({ error: 'Device selection is required' });
  }

  try {
    // Check if the device exists
    const device = db.prepare('SELECT device_ID FROM DEVICES WHERE device_ID = ?').get(device_id);
    if (!device) {
      return res.status(404).json({ error: 'Selected device not found' });
    }
    
    const subject = db.prepare(`
      SELECT sub_ID, subject_name, semester_ID
      FROM SUBJECT
      WHERE sub_ID = ? AND teacher_ID = ?
    `).get(subject_id, teacherId);

    if (!subject) {
      return res.status(403).json({
        error: 'Selected subject is not assigned to you'
      });
    }

    const semester = db.prepare(`
      SELECT semester_ID, start_date, end_date
      FROM SEMESTERS
      WHERE semester_ID = ?
    `).get(subject.semester_ID);

    if (!semester) {
      return res.status(400).json({
        error: 'The selected subject is not linked to a valid semester'
      });
    }

    const sessionStart = new Date(start_time);
    const sessionEnd = new Date(end_time);

    const semesterStart = new Date(`${semester.start_date}T00:00:00`);
    const semesterEnd = new Date(`${semester.end_date}T23:59:59`);

    if (sessionStart < semesterStart || sessionEnd > semesterEnd) {
      return res.status(400).json({
        error: `Session must be scheduled between ${semester.start_date} and ${semester.end_date}`
      });
    }

    // Auto-close any unclosed sessions for this teacher
    const nowIso = new Date().toISOString();
    db.prepare(`
      UPDATE SESSIONS 
      SET status = 0, end_time = ? 
      WHERE teacher_ID = ? AND status = 1
    `).run(nowIso, teacherId);

    // Insert new session (status 1 = In Progress, end_time = NULL)
    const result = db.prepare(`
      INSERT INTO SESSIONS (
        teacher_ID,
        device_ID,
        sub_ID,
        start_time,
        end_time,
        status
      )
      VALUES (?, ?, ?, ?, ?, 1)
    `).run(
      teacherId,
      parseInt(device_id, 10),
      parseInt(subject_id, 10),
      start_time,
      end_time
    );

    res.status(201).json({
      message: 'Instant session started',
      session_id: result.lastInsertRowid,
      start_time: nowIso,
      status: 1
    });
  } catch (err) {
    console.error('Session Start Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 6. GET CURRENT ACTIVE SESSION WITH LIVE ATTENDANCE COUNT
// -------------------------------------------------------------
router.get('/sessions/active', (req, res) => {
  const teacherId = req.teacher.id;
  // Automatically close sessions whose scheduled end time has passed
  db.prepare(`
    UPDATE SESSIONS
    SET status = 0
    WHERE teacher_ID = ?
      AND status = 1
      AND end_time IS NOT NULL
      AND datetime('now', 'localtime') >= datetime(end_time)
  `).run(teacherId);
  
  try {
    const session = db.prepare(`
      SELECT 
        s.session_ID, 
        s.device_ID, 
        s.start_time, 
        s.end_time, 
        s.status,
        d.mac_address
      FROM SESSIONS s
      LEFT JOIN DEVICES d ON s.device_ID = d.device_ID
      WHERE s.teacher_ID = ? AND s.status = 1
      ORDER BY s.session_ID DESC
      LIMIT 1
    `).get(teacherId);

    if (!session) {
      return res.json(null);
    }

    // Count attendees logged in ATTENDANCE for this session
    const attendees = db.prepare(`
      SELECT COUNT(*) as count 
      FROM ATTENDANCE 
      WHERE session_ID = ? AND LOWER(status) = 'present'
    `).get(session.session_ID)?.count || 0;

    res.json({ ...session, attendeesCount: attendees });
  } catch (err) {
    console.error('Fetch Active Session Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 7. END THE SESSION (SETS status = 0 AND WRITES end_time)
// -------------------------------------------------------------
router.put('/sessions/:id/end', (req, res) => {
  const sessionId = parseInt(req.params.id, 10);
  const teacherId = req.teacher.id;
  const endIso = new Date().toISOString();

  try {
    const result = db.prepare(`
      UPDATE SESSIONS 
      SET status = 0, end_time = ? 
      WHERE session_ID = ? AND teacher_ID = ?
    `).run(endIso, sessionId, teacherId);

    if (result.changes === 0) {
      return res.status(404).json({ error: 'Session not found or already concluded' });
    }

    res.json({ message: 'Session closed successfully', end_time: endIso });
  } catch (err) {
    console.error('End Session Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;