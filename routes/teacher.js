const express = require('express');
const router = express.Router();
const db = require('../db');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { verifyTeacherToken } = require('../middleware/teacherAuth');
const { autoCloseExpiredSessions } = require('../utils/sessionHelper');

// Helper to decode hex strings (e.g. \x445341...) if columns were stored as BYTEA
function decodeHexIfNeeded(str) {
  if (typeof str === 'string' && str.startsWith('\\x')) {
    try {
      return Buffer.from(str.slice(2), 'hex').toString('utf8');
    } catch (e) {
      return str;
    }
  }
  return str;
}

// -------------------------------------------------------------
// 1. TEACHER LOGIN
// -------------------------------------------------------------
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  try {
    const { data: teacher, error } = await db
      .from('TEACHER')
      .select('teacher_ID, name, email, pass_hash')
      .ilike('email', email.trim())
      .maybeSingle();

    if (error) throw error;

    if (!teacher) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const isMatch = bcrypt.compareSync(password, teacher.pass_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

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
router.get('/devices', async (req, res) => {
  try {
    const { data: devices, error } = await db
      .from('DEVICES')
      .select('device_ID, mac_address, status')
      .eq('status', 1)
      .order('device_ID', { ascending: true });

    if (error) throw error;

    res.json((devices || []).map(d => ({
      id: d.device_ID,
      mac_address: d.mac_address,
      status: d.status
    })));
  } catch (err) {
    console.error('Fetch devices error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 2. TEACHER PROFILE & ASSIGNED SUBJECTS
// -------------------------------------------------------------
router.get('/profile', async (req, res) => {
  const teacherId = req.teacher.id;

  try {
    const [teacherRes, subjectsRes] = await Promise.all([
      db.from('TEACHER').select('teacher_ID, name, email').eq('teacher_ID', teacherId).maybeSingle(),
      db.from('SUBJECT').select('sub_ID, subject_name').eq('teacher_ID', teacherId)
    ]);

    if (teacherRes.error) throw teacherRes.error;
    if (subjectsRes.error) throw subjectsRes.error;

    if (!teacherRes.data) {
      return res.status(404).json({ error: 'Teacher profile not found' });
    }

    res.json({
      profile: {
        id: teacherRes.data.teacher_ID,
        name: teacherRes.data.name,
        email: teacherRes.data.email
      },
      subjects: (subjectsRes.data || []).map(s => ({
        id: s.sub_ID,
        subject_name: decodeHexIfNeeded(s.subject_name)
      }))
    });
  } catch (err) {
    console.error('Teacher profile fetch error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 3. GET ENROLLED STUDENTS WITH ATTENDANCE STATS FOR SUBJECT
// -------------------------------------------------------------
router.get('/subjects/:subId/students', async (req, res) => {
  const teacherId = req.teacher.id;
  const subId = parseInt(req.params.subId, 10);

  try {
    const { data: subject, error: subErr } = await db
      .from('SUBJECT')
      .select('sub_ID, subject_name')
      .eq('sub_ID', subId)
      .eq('teacher_ID', teacherId)
      .maybeSingle();

    if (subErr) throw subErr;
    if (!subject) {
      return res.status(403).json({ error: 'Subject not found or unauthorized' });
    }

    // 1. Get completed sessions
    const { data: sessions, error: sessErr } = await db
      .from('SESSIONS')
      .select('session_ID')
      .eq('sub_ID', subId)
      .eq('teacher_ID', teacherId)
      .eq('status', 0);

    if (sessErr) throw sessErr;
    const completedSessions = sessions || [];
    const totalSessions = completedSessions.length;
    const sessionIds = completedSessions.map(s => s.session_ID);

    // 2. Get enrolled students
    const { data: enrollments, error: enrollErr } = await db
      .from('ENROLLMENTS')
      .select('stu_ID, STUDENTS(stu_ID, roll_no, name, biometric_temp)')
      .eq('sub_ID', subId);

    if (enrollErr) throw enrollErr;

    // 3. Get attendance for completed sessions
    const attendedMap = {};
    if (sessionIds.length > 0) {
      const { data: attRecords, error: attErr } = await db
        .from('ATTENDANCE')
        .select('stu_ID, session_ID')
        .in('session_ID', sessionIds)
        .ilike('status', 'present');

      if (attErr) throw attErr;

      (attRecords || []).forEach(a => {
        attendedMap[a.stu_ID] = (attendedMap[a.stu_ID] || 0) + 1;
      });
    }

    // 4. Format students report
    const students = (enrollments || [])
      .map(e => e.STUDENTS)
      .filter(Boolean)
      .map(s => {
        const attended = attendedMap[s.stu_ID] || 0;
        const absent = Math.max(0, totalSessions - attended);
        const percentage = totalSessions > 0 ? Number(((attended / totalSessions) * 100).toFixed(1)) : 0;
        const hasFingerprint = (s.biometric_temp && s.biometric_temp !== 'PENDING_ENROLLMENT' && s.biometric_temp.length > 0) ? 1 : 0;

        return {
          id: s.stu_ID,
          roll_no: s.roll_no,
          name: s.name,
          has_fingerprint: hasFingerprint,
          total_sessions: totalSessions,
          attended_sessions: attended,
          absent_sessions: absent,
          attendance_percentage: percentage
        };
      })
      .sort((a, b) => String(a.roll_no).localeCompare(String(b.roll_no)));

    res.json({
      subject: {
        ...subject,
        subject_name: decodeHexIfNeeded(subject.subject_name)
      },
      students
    });
  } catch (err) {
    console.error('Teacher enrolled students error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// INDIVIDUAL STUDENT ATTENDANCE REPORT
// -------------------------------------------------------------
router.get('/subjects/:subId/students/:studentId/report', async (req, res) => {
  const teacherId = req.teacher.id;
  const subId = parseInt(req.params.subId, 10);
  const studentId = parseInt(req.params.studentId, 10);

  try {
    // 1. Verify subject belongs to this teacher
    const { data: subject, error: subErr } = await db
      .from('SUBJECT')
      .select('sub_ID, subject_name')
      .eq('sub_ID', subId)
      .eq('teacher_ID', teacherId)
      .maybeSingle();

    if (subErr) throw subErr;
    if (!subject) {
      return res.status(403).json({ error: 'Subject not found or unauthorized' });
    }

    // 2. Find student
    const { data: student, error: stuErr } = await db
      .from('STUDENTS')
      .select('stu_ID, roll_no, name')
      .eq('stu_ID', studentId)
      .maybeSingle();

    if (stuErr) throw stuErr;
    if (!student) {
      return res.status(404).json({ error: 'Student not found' });
    }

    // 3. Get all sessions for this subject
    const { data: sessions, error: sessErr } = await db
      .from('SESSIONS')
      .select('session_ID, start_time, end_time')
      .eq('teacher_ID', teacherId)
      .eq('sub_ID', subId)
      .order('start_time', { ascending: true });

    if (sessErr) throw sessErr;
    const sessionList = sessions || [];

    // 4. Get attendance records for this student
    const sessionIds = sessionList.map(s => s.session_ID);
    let attendanceRecords = [];
    if (sessionIds.length > 0) {
      const { data: attData, error: attErr } = await db
        .from('ATTENDANCE')
        .select('session_ID, status, time_stamp')
        .eq('stu_ID', studentId)
        .in('session_ID', sessionIds);

      if (attErr) throw attErr;
      if (attData) attendanceRecords = attData;
    }

    const attendanceMap = {};
    attendanceRecords.forEach(a => {
      attendanceMap[a.session_ID] = a;
    });

    let attendedSessions = 0;
    const history = sessionList.map(s => {
      const record = attendanceMap[s.session_ID];
      const isPresent = record && String(record.status).toLowerCase() === 'present';
      if (isPresent) attendedSessions++;

      return {
        session_id: s.session_ID,
        date: s.start_time,
        start_time: s.start_time,
        status: isPresent ? 'Present' : 'Absent',
        marked_time: record?.time_stamp || 'N/A',
        marked_at: record?.time_stamp || null
      };
    });

    const totalSessions = sessionList.length;
    const absentSessions = Math.max(0, totalSessions - attendedSessions);
    const percentage = totalSessions > 0 ? Number(((attendedSessions / totalSessions) * 100).toFixed(1)) : 0;

    res.json({
      student: {
        id: student.stu_ID,
        roll_no: student.roll_no,
        name: student.name
      },
      subject: {
        sub_ID: subject.sub_ID,
        subject_name: decodeHexIfNeeded(subject.subject_name)
      },
      metrics: {
        totalSessions,
        attendedSessions,
        absentSessions,
        percentage
      },
      history
    });
  } catch (err) {
    console.error('Student report error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// COMPLETE SUBJECT ATTENDANCE REPORT
// -------------------------------------------------------------
router.get('/subjects/:subId/report', async (req, res) => {
  const teacherId = req.teacher.id;
  const subId = parseInt(req.params.subId, 10);

  try {
    // 1. Verify subject belongs to teacher
    const { data: subject, error: subErr } = await db
      .from('SUBJECT')
      .select('sub_ID, subject_name, teacher_ID, semester_ID')
      .eq('sub_ID', subId)
      .eq('teacher_ID', teacherId)
      .maybeSingle();

    if (subErr) throw subErr;
    if (!subject) {
      return res.status(403).json({ error: 'Subject not found or unauthorized' });
    }

    // Fetch teacher & semester details separately (no PostgREST FK dependency)
    const [teacherRes, semRes] = await Promise.all([
      db.from('TEACHER').select('name').eq('teacher_ID', teacherId).maybeSingle(),
      subject.semester_ID ? db.from('SEMESTERS').select('semester_name').eq('semester_ID', subject.semester_ID).maybeSingle() : Promise.resolve({ data: null })
    ]);

    const teacherName = teacherRes.data?.name || 'Unassigned';
    const semesterName = decodeHexIfNeeded(semRes.data?.semester_name) || 'Unassigned';

    // 2. Get all sessions for this subject
    const { data: sessions, error: sessErr } = await db
      .from('SESSIONS')
      .select('session_ID, start_time, end_time')
      .eq('teacher_ID', teacherId)
      .eq('sub_ID', subId)
      .order('start_time', { ascending: true });

    if (sessErr) throw sessErr;
    const sessionList = sessions || [];

    // 3. Get all students enrolled
    const { data: enrollments, error: enrollErr } = await db
      .from('ENROLLMENTS')
      .select('stu_ID, STUDENTS(stu_ID, roll_no, name)')
      .eq('sub_ID', subId);

    if (enrollErr) throw enrollErr;

    const students = (enrollments || []).map(e => e.STUDENTS).filter(Boolean);

    // 4. Get attendance records for sessions
    const sessionIds = sessionList.map(s => s.session_ID);
    let attendance = [];
    if (sessionIds.length > 0) {
      const { data: attData, error: attErr } = await db
        .from('ATTENDANCE')
        .select('session_ID, stu_ID, status')
        .in('session_ID', sessionIds);

      if (attErr) throw attErr;
      if (attData) attendance = attData;
    }

    // 5. Create attendance lookup
    const attendanceMap = {};
    attendance.forEach(record => {
      if (!attendanceMap[record.stu_ID]) {
        attendanceMap[record.stu_ID] = {};
      }
      attendanceMap[record.stu_ID][record.session_ID] = record.status;
    });

    // 6. Build complete report
    const reportStudents = students.map(student => {
      let present = 0;
      let absent = 0;

      const attList = sessionList.map(session => {
        const status = attendanceMap[student.stu_ID]?.[session.session_ID] || 'Absent';
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

      const percentage = sessionList.length > 0
        ? Number(((present / sessionList.length) * 100).toFixed(2))
        : 0;

      return {
        student_id: student.stu_ID,
        roll_no: student.roll_no,
        name: student.name,
        attendance: attList,
        present,
        absent,
        percentage
      };
    });

    res.json({
      subject: {
        sub_ID: subject.sub_ID,
        subject_name: decodeHexIfNeeded(subject.subject_name),
        teacher_name: teacherName,
        semester_name: semesterName
      },
      totalSessions: sessionList.length,
      sessions: sessionList,
      students: reportStudents
    });

  } catch (err) {
    console.error('Complete subject report error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 5. START AN INSTANT SESSION
// -------------------------------------------------------------
router.post('/sessions/start', async (req, res) => {
  const teacherId = req.teacher.id;
  const { device_id, subject_id, start_time, end_time } = req.body;

  if (!device_id) {
    return res.status(400).json({ error: 'Device selection is required' });
  }

  try {
    const { data: device, error: devErr } = await db
      .from('DEVICES')
      .select('device_ID')
      .eq('device_ID', device_id)
      .maybeSingle();

    if (devErr) throw devErr;
    if (!device) {
      return res.status(404).json({ error: 'Selected device not found' });
    }

    const { data: subject, error: subErr } = await db
      .from('SUBJECT')
      .select('sub_ID, subject_name, semester_ID')
      .eq('sub_ID', subject_id)
      .eq('teacher_ID', teacherId)
      .maybeSingle();

    if (subErr) throw subErr;
    if (!subject) {
      return res.status(403).json({ error: 'Selected subject is not assigned to you' });
    }

    const { data: semester, error: semErr } = await db
      .from('SEMESTERS')
      .select('semester_ID, start_date, end_date')
      .eq('semester_ID', subject.semester_ID)
      .maybeSingle();

    if (semErr) throw semErr;
    if (!semester) {
      return res.status(400).json({ error: 'The selected subject is not linked to a valid semester' });
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

    const nowIso = new Date().toISOString();

    // Auto-close any unclosed sessions for this teacher
    await db
      .from('SESSIONS')
      .update({ status: 0, end_time: nowIso })
      .eq('teacher_ID', teacherId)
      .eq('status', 1);

    // Insert new session (with fallback if primary key sequence is out of sync)
    let { data: newSession, error: insertErr } = await db
      .from('SESSIONS')
      .insert({
        teacher_ID: teacherId,
        device_ID: parseInt(device_id, 10),
        sub_ID: parseInt(subject_id, 10),
        start_time,
        end_time,
        status: 1
      })
      .select()
      .single();

    // If PostgreSQL sequence is desynchronized, compute next session_ID manually
    if (insertErr && (insertErr.message?.includes('SESSIONS_pkey') || insertErr.code === '23505')) {
      console.warn('SESSIONS_pkey collision detected. Calculating next available session_ID manually...');
      const { data: maxRow } = await db
        .from('SESSIONS')
        .select('session_ID')
        .order('session_ID', { ascending: false })
        .limit(1)
        .maybeSingle();

      const nextSessionId = (maxRow?.session_ID || 0) + 1;

      const retryResult = await db
        .from('SESSIONS')
        .insert({
          session_ID: nextSessionId,
          teacher_ID: teacherId,
          device_ID: parseInt(device_id, 10),
          sub_ID: parseInt(subject_id, 10),
          start_time,
          end_time,
          status: 1
        })
        .select()
        .single();

      newSession = retryResult.data;
      insertErr = retryResult.error;
    }

    if (insertErr) throw insertErr;

    res.status(201).json({
      message: 'Instant session started',
      session_id: newSession.session_ID,
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
router.get('/sessions/active', async (req, res) => {
  const teacherId = req.teacher.id;

  try {
    // 1. Auto-close any expired sessions
    await autoCloseExpiredSessions();

    const { data: session, error } = await db
      .from('SESSIONS')
      .select('session_ID, device_ID, start_time, end_time, status, DEVICES(mac_address)')
      .eq('teacher_ID', teacherId)
      .eq('status', 1)
      .order('session_ID', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (error) throw error;
    if (!session) {
      return res.json(null);
    }

    // Safety check: if session end_time is past, close it immediately
    if (session.end_time && new Date(session.end_time) <= new Date()) {
      await db
        .from('SESSIONS')
        .update({ status: 0 })
        .eq('session_ID', session.session_ID);
      return res.json(null);
    }

    // Count attendees
    const { count: attendees } = await db
      .from('ATTENDANCE')
      .select('*', { count: 'exact', head: true })
      .eq('session_ID', session.session_ID)
      .ilike('status', 'present');

    res.json({
      session_ID: session.session_ID,
      device_ID: session.device_ID,
      start_time: session.start_time,
      end_time: session.end_time,
      status: session.status,
      mac_address: session.DEVICES?.mac_address,
      attendeesCount: attendees || 0
    });
  } catch (err) {
    console.error('Fetch Active Session Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 7. END THE SESSION
// -------------------------------------------------------------
router.put('/sessions/:id/end', async (req, res) => {
  const sessionId = parseInt(req.params.id, 10);
  const teacherId = req.teacher.id;
  const endIso = new Date().toISOString();

  try {
    const { data, error } = await db
      .from('SESSIONS')
      .update({ status: 0, end_time: endIso })
      .eq('session_ID', sessionId)
      .eq('teacher_ID', teacherId)
      .select();

    if (error) throw error;
    if (!data || data.length === 0) {
      return res.status(404).json({ error: 'Session not found or already concluded' });
    }

    res.json({ message: 'Session closed successfully', end_time: endIso });
  } catch (err) {
    console.error('End Session Error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

module.exports = router;
