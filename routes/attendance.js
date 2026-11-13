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

router.post('/mark', verifyDeviceApiKey, (req, res) => {

  const { fingerprintId } = req.body;

  // -----------------------------------------------------------
  // 1. Validate fingerprint ID
  // -----------------------------------------------------------

  if (!fingerprintId) {
    return res.status(400).json({
      error: 'Fingerprint ID is required'
    });
  }

  try {

    // ---------------------------------------------------------
    // 2. Find currently active attendance session
    // ---------------------------------------------------------

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
      return res.status(404).json({
        status: 'no_active_session',
        error: 'No active attendance session found'
      });
    }


    // ---------------------------------------------------------
    // 3. TEST MAPPING
    //
    // For this first test only:
    // AS608 slot #16 -> Student ID 16
    //
    // We will replace this with proper temporary
    // slot-to-student mapping later.
    // ---------------------------------------------------------

    const studentId = parseInt(fingerprintId, 10);


    // ---------------------------------------------------------
    // 4. Find student
    // ---------------------------------------------------------

    const student = db.prepare(`
      SELECT
        stu_ID,
        name,
        roll_no
      FROM STUDENTS
      WHERE stu_ID = ?
    `).get(studentId);

    if (!student) {
      return res.status(404).json({
        status: 'unknown',
        error: 'Student not found'
      });
    }


    // ---------------------------------------------------------
    // 5. Check whether attendance is already marked
    // ---------------------------------------------------------

    const existingAttendance = db.prepare(`
        SELECT
            status
        FROM ATTENDANCE
        WHERE session_ID = ?
            AND stu_ID = ?
        `).get(
        session.session_ID,
        student.stu_ID
        );

    if (existingAttendance) {

      return res.json({
        status: 'already_marked',
        studentId: student.stu_ID,
        studentName: student.name,
        sessionId: session.session_ID
      });

    }


    // ---------------------------------------------------------
    // 6. Insert attendance
    // ---------------------------------------------------------

    db.prepare(`
      INSERT INTO ATTENDANCE (
        session_ID,
        stu_ID,
        time_stamp,
        status
      )
      VALUES (?, ?, datetime('now', 'localtime'), ?)
    `).run(
      session.session_ID,
      student.stu_ID,
      'Present'
    );


    // ---------------------------------------------------------
    // 7. Success response
    // ---------------------------------------------------------

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

    console.error(
      '[ATTENDANCE] Mark attendance error:',
      err.message
    );

    return res.status(500).json({
      error: err.message
    });

  }

});


module.exports = router;