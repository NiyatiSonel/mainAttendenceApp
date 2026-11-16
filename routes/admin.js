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

//------------------------------------------------------------
// SUPER ADMIN CONFIGURATION
//------------------------------------------------------------
const SUPER_ADMIN = {
  id: Number(process.env.SUPER_ADMIN_ID) || 1,
  name: process.env.SUPER_ADMIN_NAME || 'Super Admin',
  email: process.env.SUPER_ADMIN_EMAIL || 'superadmin@attendance.com',
  password: process.env.SUPER_ADMIN_PASSWORD || 'admin123',
  is_super: true
};

let pendingEnrollmentCommand = null;

// -------------------------------------------------------------
// 10. GET PENDING ENROLLMENT COMMAND FOR ESP32
// -------------------------------------------------------------
router.get('/pending-enrollment', verifyDeviceApiKey, async (req, res) => {
  try {
    // 0. Do not interrupt live attendance sessions with enrollment requests
    const { data: activeSession } = await db
      .from('SESSIONS')
      .select('session_ID, end_time')
      .eq('status', 1)
      .limit(1)
      .maybeSingle();

    if (activeSession && (!activeSession.end_time || new Date(activeSession.end_time) > new Date())) {
      return res.json({ enroll: false });
    }

    // 1. Check in-memory variable
    let command = pendingEnrollmentCommand;
    pendingEnrollmentCommand = null;

    // 2. If no in-memory command, check Supabase for any student with PENDING_ENROLLMENT status
    if (!command) {
      const { data: pendingStudent, error } = await db
        .from('STUDENTS')
        .select('stu_ID, roll_no')
        .eq('biometric_temp', 'PENDING_ENROLLMENT')
        .limit(1)
        .maybeSingle();

      if (!error && pendingStudent) {
        command = {
          action: 'enroll',
          studentId: pendingStudent.stu_ID,
          rollNo: pendingStudent.roll_no
        };
      }
    }

    if (!command) {
      return res.json({ enroll: false });
    }

    // Clear PENDING_ENROLLMENT in database so this request is consumed once and doesn't loop endlessly
    await db
      .from('STUDENTS')
      .update({ biometric_temp: '' })
      .eq('stu_ID', command.studentId)
      .eq('biometric_temp', 'PENDING_ENROLLMENT');

    console.log(`Sending enrollment request to ESP32 for student ID #${command.studentId}`);

    res.json({
      enroll: true,
      studentId: command.studentId,
      rollNo: command.rollNo
    });
  } catch (err) {
    console.error('Pending enrollment error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Endpoint to cancel / reset enrollment if ESP32 fails or times out
router.post('/biometrics/cancel', verifyDeviceApiKey, async (req, res) => {
  const { studentId } = req.body;
  if (studentId) {
    await db
      .from('STUDENTS')
      .update({ biometric_temp: '' })
      .eq('stu_ID', studentId)
      .eq('biometric_temp', 'PENDING_ENROLLMENT');
  }
  res.json({ success: true });
});
  } catch (err) {
    console.error('Pending enrollment error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// ESP32 - RECEIVE FINGERPRINT TEMPLATE
// -------------------------------------------------------------
router.post('/biometrics/upload', verifyDeviceApiKey, async (req, res) => {
  const { studentId, biometric_template } = req.body;

  if (!studentId) {
    return res.status(400).json({ error: 'Student ID is required' });
  }

  if (!biometric_template) {
    return res.status(400).json({ error: 'Fingerprint template is required' });
  }

  try {
    const { data: student, error: studentErr } = await db
      .from('STUDENTS')
      .select('stu_ID, roll_no, name')
      .eq('stu_ID', studentId)
      .maybeSingle();

    if (studentErr) throw studentErr;

    if (!student) {
      return res.status(404).json({ error: 'Student not found' });
    }

    const { data: updated, error: updateErr } = await db
      .from('STUDENTS')
      .update({ biometric_temp: biometric_template })
      .eq('stu_ID', studentId)
      .select();

    if (updateErr) throw updateErr;

    console.log(`Fingerprint template saved for student ID #${studentId}`);

    return res.json({
      success: true,
      message: 'Fingerprint template saved successfully',
      studentId: studentId
    });
  } catch (err) {
    console.error('Fingerprint template upload error:', err.message);
    return res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 1. ADMIN LOGIN
// -------------------------------------------------------------
router.post('/login', async (req, res) => {
  const { email, password } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: 'Email and password are required' });
  }

  // 1. Check Super Admin
  if (email.toLowerCase() === SUPER_ADMIN.email.toLowerCase()) {
    if (password === SUPER_ADMIN.password) {
      const token = jwt.sign(
        { id: SUPER_ADMIN.id, role: 'admin', isSuper: true },
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
      return res.status(401).json({ error: 'Invalid admin credentials' });
    }
  }

  // 2. Check database for normal admins
  try {
    const { data: admin, error } = await db
      .from('ADMIN')
      .select('admin_ID, name, email, pass_hash')
      .ilike('email', email.trim())
      .maybeSingle();

    if (error) throw error;

    if (!admin) {
      return res.status(401).json({ error: 'Invalid admin credentials' });
    }

    const isMatch = bcrypt.compareSync(password, admin.pass_hash);
    if (!isMatch) {
      return res.status(401).json({ error: 'Invalid admin credentials' });
    }

    const token = jwt.sign(
      { id: admin.admin_ID, role: 'admin', isSuper: false },
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
    return res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// ESP32 - PENDING ATTENDANCE SESSION
// -------------------------------------------------------------
router.get('/pending-attendance', verifyDeviceApiKey, async (req, res) => {
  try {
    // Auto-close any expired sessions
    await autoCloseExpiredSessions();

    const { data: session, error } = await db
      .from('SESSIONS')
      .select('session_ID, sub_ID, device_ID, end_time')
      .eq('status', 1)
      .order('session_ID', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (error) throw error;

    if (!session) {
      return res.json({ attendance: false });
    }

    if (session.end_time && new Date(session.end_time) <= new Date()) {
      await db.from('SESSIONS').update({ status: 0 }).eq('session_ID', session.session_ID);
      return res.json({ attendance: false });
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
router.get('/attendance-templates', verifyDeviceApiKey, async (req, res) => {
  try {
    await autoCloseExpiredSessions();

    const sessionId = parseInt(req.query.sessionId, 10);

    if (!sessionId) {
      return res.status(400).json({ error: 'Session ID is required' });
    }

    const { data: session, error: sessionErr } = await db
      .from('SESSIONS')
      .select('session_ID, sub_ID, device_ID, end_time')
      .eq('session_ID', sessionId)
      .eq('status', 1)
      .maybeSingle();

    if (sessionErr) throw sessionErr;

    if (!session || (session.end_time && new Date(session.end_time) <= new Date())) {
      if (session) {
        await db.from('SESSIONS').update({ status: 0 }).eq('session_ID', session.session_ID);
      }
      return res.status(404).json({ error: 'Active attendance session not found or expired' });
    }

    // Get enrolled students
    const { data: enrollments, error: enrollErr } = await db
      .from('ENROLLMENTS')
      .select('stu_ID')
      .eq('sub_ID', session.sub_ID);

    if (enrollErr) throw enrollErr;

    const stuIds = (enrollments || []).map(e => e.stu_ID);
    let students = [];

    if (stuIds.length > 0) {
      const { data: stuData } = await db
        .from('STUDENTS')
        .select('stu_ID, roll_no, name, biometric_temp')
        .in('stu_ID', stuIds);

      students = (stuData || [])
        .filter(s => s && s.biometric_temp && s.biometric_temp !== 'PENDING_ENROLLMENT' && s.biometric_temp !== '')
        .map(s => ({
          studentId: s.stu_ID,
          rollNo: s.roll_no,
          name: s.name,
          template: s.biometric_temp
        }));
    }

    res.json({
      success: true,
      sessionId: session.session_ID,
      subjectId: session.sub_ID,
      deviceId: session.device_ID,
      students
    });
  } catch (err) {
    console.error('Attendance templates error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// Protect all following admin routes
router.use(verifyAdminToken);

// Current admin profile / role check
router.get('/me', (req, res) => {
  res.json({
    id: req.admin.id,
    role: req.admin.role,
    isSuper: Boolean(req.admin.isSuper)
  });
});

// -------------------------------------------------------------
// 2. DASHBOARD METRICS
// -------------------------------------------------------------
router.get('/stats', async (req, res) => {
  try {
    const [students, teachers, subjects, devices] = await Promise.all([
      db.from('STUDENTS').select('*', { count: 'exact', head: true }),
      db.from('TEACHER').select('*', { count: 'exact', head: true }),
      db.from('SUBJECT').select('*', { count: 'exact', head: true }),
      db.from('DEVICES').select('*', { count: 'exact', head: true })
    ]);

    res.json({
      totalStudents: students.count || 0,
      totalTeachers: teachers.count || 0,
      totalSubjects: subjects.count || 0,
      totalDevices: devices.count || 0
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 3. TEACHER CRUD
// -------------------------------------------------------------
router.get('/teachers', async (req, res) => {
  try {
    const { data: teachers, error } = await db
      .from('TEACHER')
      .select('teacher_ID, name, email')
      .order('teacher_ID', { ascending: true });

    if (error) throw error;

    res.json((teachers || []).map(t => ({ id: t.teacher_ID, name: t.name, email: t.email })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/teachers', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email, and password required' });
  }

  try {
    const hash = bcrypt.hashSync(password, 10);
    const { data, error } = await db
      .from('TEACHER')
      .insert({ name: name.trim(), email: email.trim(), pass_hash: hash })
      .select()
      .single();

    if (error) throw error;

    res.status(201).json({ message: 'Teacher added successfully', id: data.teacher_ID });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/teachers/:id', async (req, res) => {
  const teacherId = parseInt(req.params.id, 10);
  try {
    await db.from('SUBJECT').update({ teacher_ID: null }).eq('teacher_ID', teacherId);
    const { error } = await db.from('TEACHER').delete().eq('teacher_ID', teacherId);
    if (error) throw error;
    res.json({ message: 'Teacher deleted successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// SUPERADMIN - UPDATE TEACHER PASSWORD
router.put('/teachers/:id/password', async (req, res) => {
  if (!req.admin.isSuper) {
    return res.status(403).json({ error: 'Only Super Administrator can directly edit teacher passwords.' });
  }

  const teacherId = parseInt(req.params.id, 10);
  const { new_password } = req.body;

  if (!new_password || new_password.trim().length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters long.' });
  }

  try {
    const { data: teacher, error: fetchErr } = await db
      .from('TEACHER')
      .select('teacher_ID, name')
      .eq('teacher_ID', teacherId)
      .maybeSingle();

    if (fetchErr) throw fetchErr;
    if (!teacher) {
      return res.status(404).json({ error: 'Teacher not found.' });
    }

    const pass_hash = bcrypt.hashSync(new_password.trim(), 10);
    const { error: updateErr } = await db
      .from('TEACHER')
      .update({ pass_hash })
      .eq('teacher_ID', teacherId);

    if (updateErr) throw updateErr;

    res.json({ message: `Password for teacher "${teacher.name}" updated successfully.` });
  } catch (err) {
    console.error('Update teacher password error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 4. SUBJECT CRUD & TEACHER ASSIGNMENT
// -------------------------------------------------------------
router.get('/subjects', async (req, res) => {
  try {
    const { data: subjects, error } = await db
      .from('SUBJECT')
      .select('sub_ID, subject_name, teacher_ID, semester_ID')
      .order('sub_ID', { ascending: true });

    if (error) throw error;

    const [teachersRes, semestersRes] = await Promise.all([
      db.from('TEACHER').select('teacher_ID, name'),
      db.from('SEMESTERS').select('semester_ID, semester_name')
    ]);

    const teacherMap = {};
    (teachersRes.data || []).forEach(t => { teacherMap[t.teacher_ID] = t.name; });

    const semMap = {};
    (semestersRes.data || []).forEach(s => { semMap[s.semester_ID] = decodeHexIfNeeded(s.semester_name); });

    res.json((subjects || []).map(s => ({
      id: s.sub_ID,
      subject_name: decodeHexIfNeeded(s.subject_name),
      teacher_id: s.teacher_ID,
      teacher_name: teacherMap[s.teacher_ID] || 'Unassigned',
      semester_id: s.semester_ID,
      semester_name: semMap[s.semester_ID] || 'Unassigned'
    })));
  } catch (err) {
    console.error('Fetch subjects error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

router.post('/subjects', async (req, res) => {
  const { subject_name, teacher_id, semester_id } = req.body;

  if (!subject_name) {
    return res.status(400).json({ error: 'Subject name is required' });
  }

  const parsedTeacherId = teacher_id && String(teacher_id).trim() !== '' ? parseInt(teacher_id, 10) : null;
  const parsedSemesterId = semester_id && String(semester_id).trim() !== '' ? parseInt(semester_id, 10) : null;

  try {
    const { data, error } = await db
      .from('SUBJECT')
      .insert({
        subject_name: subject_name.trim(),
        teacher_ID: parsedTeacherId,
        semester_ID: parsedSemesterId
      })
      .select()
      .single();

    if (error) throw error;

    res.status(201).json({ message: 'Subject created successfully', id: data.sub_ID });
  } catch (err) {
    console.error('Create subject error:', err.message);
    res.status(400).json({ error: err.message });
  }
});

router.put('/subjects/:id', async (req, res) => {
  const subId = parseInt(req.params.id, 10);
  const { teacher_id } = req.body;
  const parsedTeacherId = teacher_id && String(teacher_id).trim() !== '' ? parseInt(teacher_id, 10) : null;

  try {
    const { error } = await db
      .from('SUBJECT')
      .update({ teacher_ID: parsedTeacherId })
      .eq('sub_ID', subId);

    if (error) throw error;
    res.json({ message: 'Subject assignment updated' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// GET ACTIVE SEMESTERS
// -------------------------------------------------------------
router.get('/semesters', async (req, res) => {
  try {
    const { data: semesters, error } = await db
      .from('SEMESTERS')
      .select('semester_ID, semester_name, start_date, end_date, status')
      .eq('status', 1)
      .order('start_date', { ascending: false });

    if (error) throw error;

    res.json((semesters || []).map(s => ({
      id: s.semester_ID,
      semester_name: decodeHexIfNeeded(s.semester_name),
      start_date: s.start_date,
      end_date: s.end_date,
      status: s.status
    })));
  } catch (err) {
    console.error('Fetch semesters error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

router.post('/semesters', async (req, res) => {
  const { semester_name, start_date, end_date } = req.body;

  if (!semester_name || !start_date || !end_date) {
    return res.status(400).json({ error: 'Semester name, start date, and end date are required' });
  }

  if (new Date(start_date) >= new Date(end_date)) {
    return res.status(400).json({ error: 'End date must be after start date' });
  }

  try {
    const { data, error } = await db
      .from('SEMESTERS')
      .insert({
        semester_name: semester_name.trim(),
        start_date,
        end_date,
        status: 1
      })
      .select()
      .single();

    if (error) throw error;

    res.status(201).json({ message: 'Semester created successfully', id: data.semester_ID });
  } catch (err) {
    console.error('Create semester error:', err.message);
    res.status(400).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 5. STUDENTS & BIOMETRIC_TEMP ENROLLMENT
// -------------------------------------------------------------
router.get('/students', async (req, res) => {
  try {
    const { data: students, error } = await db
      .from('STUDENTS')
      .select('stu_ID, roll_no, name, biometric_temp')
      .order('stu_ID', { ascending: true });

    if (error) throw error;

    res.json((students || []).map(s => ({
      id: s.stu_ID,
      roll_no: s.roll_no,
      name: s.name,
      has_fingerprint: (s.biometric_temp && s.biometric_temp !== 'PENDING_ENROLLMENT' && s.biometric_temp.length > 0) ? 1 : 0
    })));
  } catch (err) {
    console.error('Fetch students error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

router.post('/students', async (req, res) => {
  const { roll_no, name, biometric_template } = req.body;

  if (!name || !roll_no) {
    return res.status(400).json({ error: 'Both Roll Number and Student Name are required' });
  }

  const templatePayload = biometric_template && biometric_template.trim() !== '' 
    ? biometric_template 
    : 'PENDING_ENROLLMENT';

  try {
    let { data, error } = await db
      .from('STUDENTS')
      .insert({
        roll_no: roll_no.trim(),
        name: name.trim(),
        biometric_temp: templatePayload
      })
      .select()
      .single();

    // Auto-recover if PostgreSQL sequence is desynchronized (STUDENTS_pkey collision)
    if (error && (error.code === '23505' || error.message?.includes('STUDENTS_pkey'))) {
      console.warn('[STUDENTS] Sequence collision (STUDENTS_pkey). Calculating next stu_ID manually...');
      const { data: maxRow } = await db
        .from('STUDENTS')
        .select('stu_ID')
        .order('stu_ID', { ascending: false })
        .limit(1)
        .maybeSingle();

      const nextStuId = (maxRow?.stu_ID || 0) + 1;

      const retryResult = await db
        .from('STUDENTS')
        .insert({
          stu_ID: nextStuId,
          roll_no: roll_no.trim(),
          name: name.trim(),
          biometric_temp: templatePayload
        })
        .select()
        .single();

      data = retryResult.data;
      error = retryResult.error;
    }

    if (error) throw error;

    res.status(201).json({ message: 'Student registered successfully', id: data.stu_ID });
  } catch (err) {
    console.error('Register student error:', err.message);
    res.status(400).json({ error: err.message });
  }
});

router.put('/students/:id/biometrics', async (req, res) => {
  const stuId = parseInt(req.params.id, 10);
  const { biometric_template } = req.body;

  if (!biometric_template) {
    return res.status(400).json({ error: 'Biometric template data is required' });
  }

  try {
    const { error } = await db
      .from('STUDENTS')
      .update({ biometric_temp: biometric_template })
      .eq('stu_ID', stuId);

    if (error) throw error;
    res.json({ message: 'Fingerprint enrolled successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 6. ENROLLMENTS (STUDENT-SUBJECT JUNCTION)
// -------------------------------------------------------------
router.get('/enrollments', async (req, res) => {
  try {
    const { data: enrollments, error } = await db
      .from('ENROLLMENTS')
      .select('enroll_ID, stu_ID, sub_ID')
      .order('enroll_ID', { ascending: false });

    if (error) throw error;

    const [studentsRes, subjectsRes] = await Promise.all([
      db.from('STUDENTS').select('stu_ID, roll_no, name'),
      db.from('SUBJECT').select('sub_ID, subject_name')
    ]);

    const stuMap = {};
    (studentsRes.data || []).forEach(s => { stuMap[s.stu_ID] = s; });

    const subMap = {};
    (subjectsRes.data || []).forEach(s => { subMap[s.sub_ID] = decodeHexIfNeeded(s.subject_name); });

    res.json((enrollments || []).map(e => ({
      id: e.enroll_ID,
      student_id: e.stu_ID,
      roll_no: stuMap[e.stu_ID]?.roll_no,
      student_name: stuMap[e.stu_ID]?.name,
      subject_id: e.sub_ID,
      subject_name: subMap[e.sub_ID]
    })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/enrollments', async (req, res) => {
  const { student_id, subject_id } = req.body;
  if (!student_id || !subject_id) {
    return res.status(400).json({ error: 'Select both a student and a subject' });
  }

  try {
    const { data, error } = await db
      .from('ENROLLMENTS')
      .insert({
        stu_ID: parseInt(student_id, 10),
        sub_ID: parseInt(subject_id, 10)
      })
      .select()
      .single();

    if (error) throw error;

    res.status(201).json({ message: 'Student enrolled successfully', id: data.enroll_ID });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/enrollments/:id', async (req, res) => {
  const enrollId = parseInt(req.params.id, 10);
  try {
    const { error } = await db.from('ENROLLMENTS').delete().eq('enroll_ID', enrollId);
    if (error) throw error;
    res.json({ message: 'Enrollment removed successfully' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 7. DEVICES (ESP32)
// -------------------------------------------------------------
router.get('/devices', async (req, res) => {
  try {
    const { data: devices, error } = await db
      .from('DEVICES')
      .select('device_ID, mac_address, auth_token, status');

    if (error) throw error;

    res.json((devices || []).map(d => ({
      id: d.device_ID,
      mac_address: d.mac_address,
      auth_token: d.auth_token,
      status: d.status
    })));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.post('/devices', async (req, res) => {
  const { mac_address, auth_token, status } = req.body;
  if (!mac_address) {
    return res.status(400).json({ error: 'MAC address is required' });
  }

  const deviceStatus = status !== undefined && status !== '' ? parseInt(status, 10) : 1;
  const token = auth_token || `TOKEN_${Date.now()}`;

  try {
    const { data, error } = await db
      .from('DEVICES')
      .insert({ mac_address, auth_token: token, status: deviceStatus })
      .select()
      .single();

    if (error) throw error;

    res.status(201).json({ message: 'Device registered successfully', id: data.device_ID });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 8. ADMIN MANAGEMENT
// -------------------------------------------------------------
router.get('/admins', async (req, res) => {
  try {
    let dbAdmins = [];
    try {
      const { data, error } = await db
        .from('ADMIN')
        .select('admin_ID, name, email')
        .neq('email', SUPER_ADMIN.email);
      if (!error && data) dbAdmins = data;
    } catch (e) {
      dbAdmins = [];
    }

    const formattedDbAdmins = dbAdmins.map(a => ({
      id: a.admin_ID,
      name: a.name,
      email: a.email,
      isSuper: false
    }));

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

router.post('/admins', async (req, res) => {
  const { name, email, password } = req.body;
  if (!name || !email || !password) {
    return res.status(400).json({ error: 'Name, email, and password are required' });
  }

  try {
    const hash = bcrypt.hashSync(password, 10);
    const { data, error } = await db
      .from('ADMIN')
      .insert({ name, email, pass_hash: hash })
      .select()
      .single();

    if (error) throw error;

    res.status(201).json({ message: 'Admin added successfully', id: data.admin_ID });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

router.delete('/admins/:id', async (req, res) => {
  const targetId = parseInt(req.params.id, 10);

  if (!req.admin.isSuper && req.admin.id === targetId) {
    return res.status(400).json({ error: 'You cannot delete your own active administrator account.' });
  }

  try {
    const { data, error } = await db
      .from('ADMIN')
      .delete()
      .eq('admin_ID', targetId)
      .select();

    if (error) throw error;

    if (!data || data.length === 0) {
      return res.status(404).json({ error: 'Admin account not found in database.' });
    }

    res.json({ message: 'Administrator account deleted successfully.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// SUPERADMIN - UPDATE ADMIN PASSWORD
router.put('/admins/:id/password', async (req, res) => {
  if (!req.admin.isSuper) {
    return res.status(403).json({ error: 'Only Super Administrator can directly edit administrator passwords.' });
  }

  const targetId = parseInt(req.params.id, 10);
  if (targetId === 0) {
    return res.status(400).json({ error: 'Super Admin password is configured via server environment variables.' });
  }

  const { new_password } = req.body;
  if (!new_password || new_password.trim().length < 6) {
    return res.status(400).json({ error: 'New password must be at least 6 characters long.' });
  }

  try {
    const { data: admin, error: fetchErr } = await db
      .from('ADMIN')
      .select('admin_ID, name')
      .eq('admin_ID', targetId)
      .maybeSingle();

    if (fetchErr) throw fetchErr;
    if (!admin) {
      return res.status(404).json({ error: 'Admin account not found in database.' });
    }

    const pass_hash = bcrypt.hashSync(new_password.trim(), 10);
    const { error: updateErr } = await db
      .from('ADMIN')
      .update({ pass_hash })
      .eq('admin_ID', targetId);

    if (updateErr) throw updateErr;

    res.json({ message: `Password for admin "${admin.name}" updated successfully.` });
  } catch (err) {
    console.error('Update admin password error:', err.message);
    res.status(500).json({ error: err.message });
  }
});

// -------------------------------------------------------------
// 9. TRIGGER FINGERPRINT ENROLLMENT (BRIDGE)
// -------------------------------------------------------------
router.post('/students/:id/trigger-enroll', async (req, res) => {
  const stuId = parseInt(req.params.id, 10);
  const { roll_no } = req.body;

  try {
    const { data: student, error } = await db
      .from('STUDENTS')
      .select('*')
      .eq('stu_ID', stuId)
      .maybeSingle();

    if (error) throw error;
    if (!student) {
      return res.status(404).json({ error: 'Student not found' });
    }

    // Update student to PENDING_ENROLLMENT in database so request is persisted across Vercel instances
    await db
      .from('STUDENTS')
      .update({ biometric_temp: 'PENDING_ENROLLMENT' })
      .eq('stu_ID', stuId);

    pendingEnrollmentCommand = {
      action: 'enroll',
      studentId: stuId,
      rollNo: roll_no || student.roll_no,
      timestamp: Date.now()
    };

    console.log(`Enrollment request created for student ID #${stuId}`);
    res.json({ message: `Enrollment request created for student ID #${stuId}.` });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

router.get('/hardware/pending-command', (req, res) => {
  const cmd = pendingEnrollmentCommand;
  pendingEnrollmentCommand = null;
  res.json(cmd || { action: 'none' });
});

module.exports = router;
