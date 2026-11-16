const db = require('../db');

/**
 * Automatically closes any active sessions (status = 1) whose end_time has passed.
 */
async function autoCloseExpiredSessions() {
  try {
    const now = new Date();
    const nowIso = now.toISOString();

    // 1. Fetch currently active sessions
    const { data: activeSessions, error } = await db
      .from('SESSIONS')
      .select('session_ID, end_time')
      .eq('status', 1);

    if (error || !activeSessions || activeSessions.length === 0) return;

    const expiredIds = [];
    for (const s of activeSessions) {
      if (!s.end_time) continue;
      const endTimeDate = new Date(s.end_time);
      if (!isNaN(endTimeDate.getTime()) && endTimeDate <= now) {
        expiredIds.push(s.session_ID);
      }
    }

    if (expiredIds.length > 0) {
      await db
        .from('SESSIONS')
        .update({ status: 0 })
        .in('session_ID', expiredIds);
      console.log(`[AUTO-CLOSE] Successfully auto-closed expired sessions: ${expiredIds.join(', ')}`);
    }
  } catch (err) {
    console.error('[AUTO-CLOSE] Error auto-closing expired sessions:', err.message);
  }
}

module.exports = { autoCloseExpiredSessions };
