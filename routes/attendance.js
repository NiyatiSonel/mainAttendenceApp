require('dotenv').config();

const express = require('express');
const router = express.Router();

const db = require('../db');

const {
  verifyDeviceApiKey
} = require('../middleware/auth');

// =============================================================
// MARK ATTENDANCE FROM ESP32
// =============================================================

router.post('/mark', verifyDeviceApiKey, async (req, res) => {
  const { fingerprintId } = req.body;

  // 1. Validate fingerprint ID
  if (!fingerprintId) {
    return res.status(400).json({
      error: 'Fingerprint ID is required'
    });
  }

  try {
    // 2. Find currently active attendance session
    const { data: session, error: sessionErr } = await db
      .from('SESSIONS')
      .select('session_ID, sub_ID, device_ID')
      .eq('status', 1)
      .order('session_ID', { ascending: false })
      .limit(1)
      .maybeSingle();

    if (sessionErr) throw sessionErr;

    if (!session) {
      return res.status(404).json({
        status: 'no_active_session',
        error: 'No active attendance session found'
      });
    }

    // 3. Mapping: fingerprint ID -> Student ID
    const studentId = parseInt(fingerprintId, 10);

    // 4. Find student
    const { data: student, error: studentErr } = await db
      .from('STUDENTS')
      .select('stu_ID, name, roll_no')
      .eq('stu_ID', studentId)
      .maybeSingle();

    if (studentErr) throw studentErr;

    if (!student) {
      return res.status(404).json({
        status: 'unknown',
        error: 'Student not found'
      });
    }

    // 5. Check whether attendance is already marked
    const { data: existingAttendance, error: existErr } = await db
      .from('ATTENDANCE')
      .select('status')
      .eq('session_ID', session.session_ID)
      .eq('stu_ID', student.stu_ID)
      .maybeSingle();

    if (existErr) throw existErr;

    if (existingAttendance) {
      return res.json({
        status: 'already_marked',
        studentId: student.stu_ID,
        studentName: student.name,
        sessionId: session.session_ID
      });
    }

    // 6. Insert attendance
    const { error: insertErr } = await db
      .from('ATTENDANCE')
      .insert({
        session_ID: session.session_ID,
        stu_ID: student.stu_ID,
        time_stamp: new Date().toISOString(),
        status: 'Present'
      });

    if (insertErr) throw insertErr;

    // 7. Success response
    console.log(
      `[ATTENDANCE] Student ${student.stu_ID} (${student.name}) marked Present for session ${session.session_ID}`
    );

    return res.json({
      status: 'marked',
      studentId: student.stu_ID,
      studentName: student.name,
      sessionId: session.session_ID
    });

  } catch (err) {
    console.error('[ATTENDANCE] Mark attendance error:', err.message);
    return res.status(500).json({
      error: err.message
    });
  }
});

module.exports = router;
