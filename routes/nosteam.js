// routes/nosteam.js
// -----------------------------------------------------------------------------
// Bind a player’s SteamID (or No‑Steam ID) to their site account so that the
// AMXX plugin can later enforce nicknames and verify identity.
// -----------------------------------------------------------------------------

const express = require('express');
const router  = express.Router();
const mysql   = require('mysql2/promise');

// ──────────────────────────────────────────────────────────────────────────────
// middleware/auth.js must export  `ensureAuthenticated`
// (server.js already pulls the same helper)
// ──────────────────────────────────────────────────────────────────────────────
const { ensureAuthenticated } = require('../middleware/auth');

// Database connection details – identical to server.js but pointing at
// the  nosteam_users  schema.
const dbConfig = {
  host:     process.env.DB_HOST,
  user:     process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: 'nosteam_users',
  waitForConnections: true,
  connectionLimit: 5,
  queueLimit: 0
};

// Convenience wrapper
const getDb = () => mysql.createConnection(dbConfig);

// ──────────────────────────────────────────────────────────────────────────────
// POST  /nosteam/bind-steamid
// Body: { steamid: "STEAM_0:0:12345" }
// Upserts (user_id, steamid, username) into  bindings
// ──────────────────────────────────────────────────────────────────────────────
router.post('/bind-steamid', ensureAuthenticated, async (req, res) => {
  const { steamid }   = req.body;
  const   username    = req.user.username;  // from Passport session
  const   userId      = req.user.id;

  if (!/^STEAM_[01]:[01]:\d+$/.test(steamid)) {
    return res.status(400).json({ error: 'Invalid SteamID format.' });
  }

  try {
    const db = await getDb();

    // Ensure the SteamID isn’t already tied to somebody else
    const [taken] = await db.query(
      'SELECT user_id FROM bindings WHERE steamid = ? LIMIT 1',
      [steamid]
    );

    if (taken.length && taken[0].user_id !== userId) {
      await db.end();
      return res.status(409).json({ error: 'SteamID already in use by another account.' });
    }

    // Upsert
    await db.query(
      `INSERT INTO bindings (user_id, steamid, username)
       VALUES (?, ?, ?)
       ON DUPLICATE KEY UPDATE
           steamid  = VALUES(steamid),
           username = VALUES(username),
           created_at = NOW()`,
      [userId, steamid, username]
    );

    await db.end();
    res.json({ success: true, steamid, username });
  } catch (err) {
    console.error('[nosteam] bind-steamid error:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// GET  /nosteam/my-steamid
// Returns  { steamid, username }
// ──────────────────────────────────────────────────────────────────────────────
router.get('/my-steamid', ensureAuthenticated, async (req, res) => {
  try {
    const db = await getDb();

    const [rows] = await db.query(
      'SELECT steamid, username FROM bindings WHERE user_id = ? LIMIT 1',
      [req.user.id]
    );

    await db.end();

    if (!rows.length) {
      return res.status(404).json({ error: 'No binding found for this account.' });
    }

    res.json({
      steamid:  rows[0].steamid,
      username: rows[0].username
    });
  } catch (err) {
    console.error('[nosteam] my-steamid error:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

// ──────────────────────────────────────────────────────────────────────────────
// DELETE  /nosteam/unbind-steamid
// Removes the binding (optional but handy for admins/testing)
// ──────────────────────────────────────────────────────────────────────────────
router.delete('/unbind-steamid', ensureAuthenticated, async (req, res) => {
  try {
    const db = await getDb();
    await db.query('DELETE FROM bindings WHERE user_id = ?', [req.user.id]);
    await db.end();
    res.json({ success: true });
  } catch (err) {
    console.error('[nosteam] unbind-steamid error:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

module.exports = router;
