require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const passport = require('passport');
const SteamStrategy = require('passport-steam').Strategy;
const LocalStrategy = require('passport-local').Strategy;
const session = require('express-session');
const { KubeConfig, BatchV1Api } = require('@kubernetes/client-node');
const fs = require('fs');
const yaml = require('js-yaml');
const crypto = require('crypto');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const bodyParser = require('body-parser');

// Steam ID conversion utility
function steam64ToLegacy(steamId64) {
  const steamId = BigInt(steamId64);
  const universe = steamId >> 56n;
  const base = 76561197960265728n;
  const diff = steamId - base;
  const y = diff % 2n;
  const z = (diff - y) / 2n;
  return `STEAM_${universe}:${y}:${z}`;
}

// Captain config
let captainConfig = { steamIds: [], emails: [] };
try {
  const configData = fs.readFileSync(path.join(__dirname, 'captains.json'), 'utf8');
  captainConfig = JSON.parse(configData);
} catch (err) {
  console.error("Error reading captain configuration:", err);
}

const DEFAULT_PROFILE_PICTURE = '/img/fallback-pfp.png';
const MAX_SERVER_AGE = 7200000; // 2 hours in ms

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// K8s
const kc = new KubeConfig();
kc.loadFromDefault();
const k8sBatchApi = kc.makeApiClient(BatchV1Api);

const PORT = 3000;

// DB configs
const dbConfigMatchmaking = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: 'cs_matchmaking'
};
const dbConfigStats = {
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: 'stats'
};

// Serve static
app.use(express.static(path.join(__dirname, 'public')));

// Sessions & body parser
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));
app.use(bodyParser.urlencoded({ extended: false }));

// Passport
app.use(passport.initialize());
app.use(passport.session());

// Steam Strategy
passport.use(new SteamStrategy({
  returnURL: 'http://192.168.2.69:3000/auth/steam/callback',
  realm: 'http://192.168.2.69:3000/',
  apiKey: process.env.STEAM_API_KEY,
  passReqToCallback: true
}, async (req, identifier, profile, done) => {
  try {
    profile.username = profile.displayName || 'Unknown user';
    profile.photos = profile.photos || [{ value: DEFAULT_PROFILE_PICTURE }];
    profile.steamId = profile.id;

    const db = await mysql.createConnection(dbConfigMatchmaking);
    const [rows] = await db.query('SELECT * FROM users WHERE steam_id = ?', [profile.steamId]);

    let user;
    if (rows.length === 0) {
      // Insert new user
      const [insertResult] = await db.query(
        `INSERT INTO users (username, steam_id, profile_picture, role, status, password_hash)
         VALUES (?, ?, ?, ?, ?, ?)`,
        [profile.username, profile.steamId, profile.photos[0].value, 'user', 'active', '']
      );
      const userId = insertResult.insertId;

      const dbStats = await mysql.createConnection(dbConfigStats);
      await dbStats.query('INSERT INTO ultimate_stats (steamid, skill) VALUES (?, ?)', [profile.steamId, 0]);
      await dbStats.end();

      user = {
        id: userId,
        username: profile.username,
        steamId: profile.steamId,
        profile_picture: profile.photos[0].value,
        role: 'user',
        status: 'active'
      };
    } else {
      // Update existing user
      await db.query(
        'UPDATE users SET username = ?, profile_picture = ? WHERE steam_id = ?',
        [profile.username, profile.photos[0].value, profile.steamId]
      );
      user = rows[0];
      user.steamId = user.steam_id;
      user.profile_picture = user.profile_picture || DEFAULT_PROFILE_PICTURE;
    }
    await db.end();
    return done(null, user);
  } catch (error) {
    console.error('Error in SteamStrategy:', error);
    return done(error, null);
  }
}));

// Local Strategy
passport.use('local', new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password'
}, async (email, password, done) => {
  try {
    const db = await mysql.createConnection(dbConfigMatchmaking);
    const [rows] = await db.query('SELECT * FROM users WHERE email = ?', [email]);
    await db.end();
    if (rows.length === 0) {
      return done(null, false, { message: 'Incorrect email.' });
    }
    const user = rows[0];
    const match = await bcrypt.compare(password, user.password_hash);
    if (!match) {
      return done(null, false, { message: 'Incorrect password.' });
    }
    return done(null, user);
  } catch (err) {
    return done(err);
  }
}));

passport.serializeUser((user, done) => {
  done(null, { id: user.id, type: user.steamId ? 'steam' : 'local' });
});
passport.deserializeUser(async (obj, done) => {
  try {
    const db = await mysql.createConnection(dbConfigMatchmaking);
    const [rows] = await db.query('SELECT * FROM users WHERE id = ?', [obj.id]);
    await db.end();
    if (rows.length === 0) {
      return done(new Error('User not found'));
    }
    const user = rows[0];
    if (obj.type === 'steam') {
      user.steamId = user.steam_id;
      user.profile_picture = user.profile_picture || DEFAULT_PROFILE_PICTURE;
    }
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Helpers
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect('/login');
}
function ensureAdmin(req, res, next) {
  if (req.isAuthenticated() && req.user.role === 'admin') return next();
  res.redirect('/login');
}
function generateUniqueName(baseName) {
  const randomString = crypto.randomBytes(4).toString('hex');
  return `${baseName}-${randomString}`.toLowerCase();
}
function getRandomPort() {
  const min = 27015;
  const max = 27030;
  return Math.floor(Math.random() * (max - min + 1)) + min;
}
function generateInviteCode() {
  return crypto.randomBytes(4).toString('hex');
}

// Helper to fetch player skill
async function getPlayerSkill(user, dbStats) {
  if (!user) return 0;
  try {
    let query;
    let params;
    if (user.steamId) {
      query = `SELECT skill FROM ultimate_stats WHERE steamid = ? OR name = ?`;
      params = [user.steamId, user.username || ''];
    } else if (user.email) {
      query = `SELECT skill FROM ultimate_stats WHERE steamid = ? OR name = ?`;
      params = [user.email, user.username || ''];
    } else {
      // Fallback if no identifier, though should have one by this point
      return 0;
    }
    const [rows] = await dbStats.query(query, params);
    return rows.length > 0 ? rows[0].skill : 0;
  } catch (error) {
    console.error(`Error fetching skill for user ${user.id || user.username}:`, error);
    return 0; // Return default skill on error
  }
}

// K8s job creation
async function createOrUpdateCsServerJob(lobbyId, mapName) {
  const port = getRandomPort();
  const jobName = generateUniqueName(`cs-server-${lobbyId}`);
  const templatePath = path.join(__dirname, 'k3s-manifest.yaml');
  let manifestTemplate = fs.readFileSync(templatePath, 'utf8');
  manifestTemplate = manifestTemplate
    .replace(/{{jobName}}/g, jobName)
    .replace(/{{port}}/g, port.toString())
    .replace(/{{mapName}}/g, mapName);
  const manifest = yaml.load(manifestTemplate);
  try {
    await k8sBatchApi.createNamespacedJob('default', manifest);
    console.log(`Job created: ${jobName} on port ${port}`);
    return { port, jobName };
  } catch (error) {
    console.error('Error creating job:', error);
    throw error;
  }
}

// Express routes
const appRoutes = () => {
  app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
  });

  app.get('/auth/steam', passport.authenticate('steam'));
  app.get('/auth/steam/callback',
    passport.authenticate('steam', { failureRedirect: '/' }),
    (req, res) => { res.redirect('/profile'); }
  );

  app.post('/login', passport.authenticate('local', {
    successRedirect: '/profile',
    failureRedirect: '/login?error=1'
  }));

  app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;
    if (!username || !email || !password) {
      return res.status(400).send('Please fill all fields.');
    }
    try {
      const db = await mysql.createConnection(dbConfigMatchmaking);
      const passwordHash = await bcrypt.hash(password, 10);
      const [result] = await db.query(
        `INSERT INTO users (username, email, password_hash, role, status)
         VALUES (?, ?, ?, ?, ?)`,
        [username, email, passwordHash, 'user', 'active']
      );
      const userId = result.insertId;

      const dbStats = await mysql.createConnection(dbConfigStats);
      await dbStats.query('INSERT INTO ultimate_stats (steamid, skill) VALUES (?, ?)', [email, 0]);
      await dbStats.end();
      await db.end();
      res.redirect('/login');
    } catch (err) {
      console.error('Registration error:', err);
      res.status(500).send('Server error.');
    }
  });

  app.get('/register', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'register.html'));
  });

  app.get('/login', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'login.html'));
  });

  app.get('/profile', ensureAuthenticated, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'profile.html'));
  });

  app.get('/user/info', ensureAuthenticated, (req, res) => {
    const user = req.user;
    // --- DEBUGGING ---
    console.log(`[User Info] User object for ID ${user.id}:`, JSON.stringify(user, null, 2));
    // --- END DEBUGGING ---
    res.json({
      id: user.id,
      username: user.username, // Still sending user.username
      steamId: user.steamId || null,
      email: user.email || null,
      profilePictureUrl: user.profile_picture || DEFAULT_PROFILE_PICTURE
    });
  });

  app.get('/user/skill', ensureAuthenticated, async (req, res) => {
    const user = req.user;
    const db = await mysql.createConnection(dbConfigStats);
    try {
      let query;
      let params;

      if (user.steamId) {
        // Steam user: Look up by steamId (primary) or username (fallback)
        query = `SELECT skill FROM ultimate_stats WHERE steamid = ? OR name = ?`;
        params = [user.steamId, user.username || ''];
      } else if (user.email) {
        // Local user: Look up by email (stored in steamid column during registration) or username (fallback)
        query = `SELECT skill FROM ultimate_stats WHERE steamid = ? OR name = ?`;
        params = [user.email, user.username || ''];
      } else {
        // Should not happen if authenticated, but handle defensively
        res.status(404).json({ message: 'Player skill not found (no identifier)' });
        await db.end();
        return;
      }

      const [rows] = await db.query(query, params);

      if (rows.length > 0) {
        res.json({ skill: rows[0].skill });
      } else {
        res.status(404).json({ message: 'Player skill not found' });
      }
    } catch (error) {
      console.error('Error fetching player skill:', error);
      res.status(500).json({ error: 'Database error' });
    } finally {
      await db.end();
    }
  });

  app.get('/api/player/:id/stats', ensureAuthenticated, async (req, res) => {
    try {
      const dbMatchmaking = await mysql.createConnection(dbConfigMatchmaking);
      const dbStats = await mysql.createConnection(dbConfigStats);

      let user;
      if (req.params.id === 'me') {
        [user] = await dbMatchmaking.query('SELECT * FROM users WHERE id = ?', [req.user.id]);
      } else {
        [user] = await dbMatchmaking.query('SELECT * FROM users WHERE id = ?', [req.params.id]);
      }
      if (!user.length) {
        await dbMatchmaking.end();
        await dbStats.end();
        return res.status(404).json({ error: 'User not found' });
      }
      const userData = user[0];

      let identifier;
      if (userData.steam_id) {
        identifier = steam64ToLegacy(userData.steam_id);
      } else {
        identifier = userData.username;
      }

      const [stats] = await dbStats.query(
        `SELECT * FROM ultimate_stats
         WHERE steamid = ? OR name = ?
         ORDER BY last_visit DESC LIMIT 1`,
        [identifier, userData.username]
      );

      let weapons = [];
      if (stats && stats.length > 0) {
        const statsRowId = stats[0].id;
        [weapons] = await dbStats.query(
          `SELECT weapon, kills, hs_kills, damage
           FROM ultimate_stats_weapons
           WHERE player_id = ?`,
          [statsRowId]
        );
      }

      await dbMatchmaking.end();
      await dbStats.end();

      const response = {
        id: userData.id,
        name: userData.username,
        profile_picture: userData.profile_picture || DEFAULT_PROFILE_PICTURE,

        skill: stats[0]?.skill || 0,
        kills: stats[0]?.kills || 0,
        deaths: stats[0]?.deaths || 0,
        hs_kills: stats[0]?.hs_kills || 0,
        hits: stats[0]?.hits || 0,
        shots: stats[0]?.shots || 1,
        rounds: stats[0]?.rounds || 0,
        time: stats[0]?.time || 0,
        wins_ct: stats[0]?.wins_ct || 0,
        wins_t: stats[0]?.wins_t || 0,
        planted: stats[0]?.planted || 0,
        defused: stats[0]?.defused || 0,
        assists: stats[0]?.assists || 0,
        revenges: stats[0]?.revenges || 0,
        survived: stats[0]?.survived || 0,
        trade_kills: stats[0]?.trade_kills || 0,
        damage: stats[0]?.damage || 0,
        team_kills: stats[0]?.team_kills || 0,

        weapons: weapons || []
      };
      res.json(response);
    } catch (error) {
      console.error('Player stats error:', error);
      res.status(500).json({ error: 'Server error', details: error.message });
    }
  });

  app.get('/api/server/stats', ensureAuthenticated, async (req, res) => {
    try {
      const db = await mysql.createConnection(dbConfigMatchmaking);
      const [queueResult] = await db.query('SELECT COUNT(*) as count FROM queue');
      const queuedPlayers = queueResult[0].count;

      const [matchesResult] = await db.query(
        `SELECT COUNT(DISTINCT lobby_id) as count
         FROM players
         WHERE lobby_id IS NOT NULL`
      );
      const activeMatches = matchesResult[0].count;

      await db.end();
      res.json({
        queuedPlayers,
        activeMatches
      });
    } catch (error) {
      console.error('Server stats error:', error);
      res.status(500).json({ error: 'Server error', details: error.message });
    }
  });

  // Admin
  app.get('/admin', ensureAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
  });
  app.get('/admin/users', ensureAdmin, async (req, res) => {
    try {
      const db = await mysql.createConnection(dbConfigMatchmaking);
      const [users] = await db.query('SELECT id, username, email, status, role FROM users');
      await db.end();
      res.json(users);
    } catch (err) {
      console.error('Error fetching users:', err);
      res.status(500).json({ error: 'Database error' });
    }
  });
  app.post('/admin/updateUser', ensureAdmin, express.json(), async (req, res) => {
    const { userId, status, role } = req.body;
    try {
      const db = await mysql.createConnection(dbConfigMatchmaking);
      await db.query(
        'UPDATE users SET status = ?, role = ? WHERE id = ?',
        [status, role, userId]
      );
      await db.end();
      res.json({ success: true });
    } catch (err) {
      console.error('Error updating user:', err);
      res.status(500).json({ error: 'Database error' });
    }
  });
};

// -----------------------------------------------------------------------
// LOBBY & PRE-LOBBY DATA
// -----------------------------------------------------------------------
let lobbies = {};       // final in-game lobbies
let banTimers = {};     // for countdown

// pre-lobby structure
let preLobbies = {};
let userPreLobbyMap = {};

// Structure to track ongoing match ready checks
// Key: A unique check ID (can be the potential lobbyId)
// Value: { players: { socketId: { accepted: boolean, userId: number, ...other data } }, timer: NodeJS.Timeout, lobbyId: string, totalPlayers: number }
let matchReadyChecks = {};
const MATCH_READY_TIMEOUT = 30000; // 30 seconds for check-in

/**
 * startCountdown: calls autoBan if time runs out
 */
function startCountdown(lobbyId, currentTurn) {
  let countdown = 10;
  function tick() {
    io.to(lobbyId).emit('countdownTick', { time: countdown, currentTurn });
    if (countdown <= 0) {
      autoBan(lobbyId, currentTurn);
    } else {
      countdown--;
      banTimers[lobbyId] = { timer: setTimeout(tick, 1000) };
    }
  }
  banTimers[lobbyId] = { timer: setTimeout(tick, 1000) };
}

async function autoBan(lobbyId, currentTurn) {
  const lobby = lobbies[lobbyId];
  if (!lobby) return;
  const remaining = lobby.availableMaps.filter(m => !lobby.bannedMaps.includes(m));
  if (remaining.length === 0) return;

  // auto-banish the first
  const autoBannedMap = remaining[0];
  lobby.bannedMaps.push(autoBannedMap);
  io.to(lobbyId).emit('mapBanned', { mapName: autoBannedMap });

  const newRemaining = lobby.availableMaps.filter(m => !lobby.bannedMaps.includes(m));
  if (newRemaining.length === 1) {
    // orchestrate
    if (!lobby.serverCreated) {
      lobby.serverCreated = true;
      const finalMap = newRemaining[0];
      const { port, jobName } = await createOrUpdateCsServerJob(lobbyId, finalMap);
      lobby.jobName = jobName;
      io.to(lobbyId).emit('lobbyCreated', { serverIp: '192.168.2.69', serverPort: port, mapName: finalMap });
      lobby.turn = null;
      if (banTimers[lobbyId]?.timer) clearTimeout(banTimers[lobbyId].timer);
    }
    return;
  }

  // switch turn
  lobby.turn = (lobby.turn === 'team1') ? 'team2' : 'team1';
  io.to(lobbyId).emit('turnChanged', { currentTurn: lobby.turn });
  startCountdown(lobbyId, lobby.turn);
}

/**
 * Leaves or kicks a user from a pre-lobby
 */
function leavePreLobbyInternal(inviteCode, socketId, kicked = false) {
  const preLobby = preLobbies[inviteCode];
  if (!preLobby) return;

  // remove user from array
  const idx = preLobby.players.findIndex(p => p.socketId === socketId);
  if (idx >= 0) {
    const removedPlayer = preLobby.players.splice(idx, 1)[0];
    delete userPreLobbyMap[socketId];

    if (kicked) {
      io.to(socketId).emit('kickedFromPreLobby', { inviteCode });
    } else {
      io.to(socketId).emit('preLobbyLeft', { inviteCode });
    }

    // if the leader left
    if (preLobby.leaderSocketId === socketId) { // Check against leaderSocketId
      if (preLobby.players.length > 0) {
        // Assign the *next* player (now the first) as the new leader
        const newLeader = preLobby.players[0];
        preLobby.leaderSocketId = newLeader.socketId;
        preLobby.leaderUserId = newLeader.id; // <-- IMPORTANT: Update leaderUserId
        console.log(`[PreLobby ${inviteCode}] Leader left. New leader assigned: User ID ${newLeader.id}, Socket ID ${newLeader.socketId}`);
      } else {
        // Lobby is empty, delete it
        console.log(`[PreLobby ${inviteCode}] Leader left. Lobby is now empty and will be deleted.`);
        delete preLobbies[inviteCode];
        // No need to broadcast update if lobby is deleted
        return; // Exit early
      }
    }

    // broadcast updated list (only if lobby still exists)
    if (preLobbies[inviteCode]) {
      io.to(`preLobby_${inviteCode}`).emit('preLobbyUpdated', {
        inviteCode,
        players: preLobby.players,
        leaderUserId: preLobby.leaderUserId // Include leader ID
      });
    }
  }
}

/**
 * Attempt to form a final-lobby from the queue
 */
async function checkQueueAndFormLobby(matchmakingQueue, db) {
  const groupedPlayers = {};

  for (const queued of matchmakingQueue) {
    const [playerData] = await db.query('SELECT * FROM players WHERE id = ?', [queued.playerId]);
    if (!playerData || playerData.length === 0) continue;
    const playerRow = playerData[0];

    // fetch ELO
    const dbStats = await mysql.createConnection(dbConfigStats);
    const [eloRows] = await dbStats.query(
      'SELECT skill FROM ultimate_stats WHERE steamid = ? OR name = ?',
      [playerRow.steam_id, playerRow.name]
    );
    await dbStats.end();
    const elo = eloRows[0]?.skill || 0;

    // group them by group_id or fallback to "solo_<id>"
    const groupId = playerRow.group_id || `solo_${playerRow.id}`;
    if (!groupedPlayers[groupId]) groupedPlayers[groupId] = [];
    groupedPlayers[groupId].push({ ...playerRow, elo });
  }

  // for a simple test, requiring 4 players total
  const requiredPlayers = 2;

  const groups = Object.values(groupedPlayers);
  let lobbyPlayers = [];

  // fill up to requiredPlayers
  while (groups.length > 0 && lobbyPlayers.length < requiredPlayers) {
    const group = groups.shift();
    if (lobbyPlayers.length + group.length <= requiredPlayers) {
      lobbyPlayers = lobbyPlayers.concat(group);
    } else {
      groups.push(group);
      break;
    }
  }

  // if we have exactly enough
  if (lobbyPlayers.length === requiredPlayers) {
    const lobbyId = generateUniqueName('lobby');
    const team1 = [];
    const team2 = [];
    const playerGroupsInLobby = {}; // Store groups that are part of this lobby

    // Reconstruct which groups are in the lobby based on group_id or solo status
    lobbyPlayers.forEach(p => {
        const groupId = p.group_id || `solo_${p.id}`; // Use group_id if present, else treat as solo
        if (!playerGroupsInLobby[groupId]) {
            playerGroupsInLobby[groupId] = [];
        }
        playerGroupsInLobby[groupId].push(p);
    });

    // Assign entire groups to teams for balance
    Object.values(playerGroupsInLobby).forEach(group => {
        const targetTeamList = team1.length <= team2.length ? team1 : team2;
        const targetTeamName = team1.length <= team2.length ? 'team1' : 'team2';
        group.forEach(player => {
            player.team = targetTeamName; // Set the team property on the player
            targetTeamList.push(player);  // Add player to the correct team list
        });
    });

    // designate captains (function remains the same, but operates on group-aware teams)
    function designateCaptain(team) {
      if (!team || team.length === 0) return null; // Handle empty team case
      const priorityCandidate = team.find(p => {
        const sid = p.steam_id;
        if (sid && captainConfig.steamIds.includes(sid)) return true;
        if (p.email && captainConfig.emails.includes(p.email)) return true;
        return false;
      });
      return priorityCandidate || team[0];
    }
    const captainTeam1 = designateCaptain(team1);
    const captainTeam2 = designateCaptain(team2);

    // Reset captain flags for all players in the lobby first
    lobbyPlayers.forEach(p => p.captain = false);

    // Set the captain flag only for the designated captains
    if (captainTeam1) captainTeam1.captain = true;
    if (captainTeam2) captainTeam2.captain = true;

    // --- START MATCH READY CHECK ---
    const checkId = lobbyId; // Use the potential lobbyId as the check ID
    const playersForCheck = {};
    lobbyPlayers.forEach(p => {
      playersForCheck[p.socket_id] = { // Use socket_id as the key within the check
        accepted: false,
        userId: p.user_id || p.id, // Store user ID for potential re-queue
        playerData: p // Store the full player data temporarily
      };
    });

    matchReadyChecks[checkId] = {
      players: playersForCheck,
      lobbyId: lobbyId, // Store the intended lobbyId
      totalPlayers: requiredPlayers,
      teams: { team1, team2 }, // Store proposed teams
      captains: { // Store proposed captains
        team1: captainTeam1 ? (captainTeam1.user_id || captainTeam1.id) : null,
        team2: captainTeam2 ? (captainTeam2.user_id || captainTeam2.id) : null
      },
      timer: setTimeout(() => handleMatchReadyTimeout(checkId), MATCH_READY_TIMEOUT),
      // Store other necessary info temporarily if needed
      availableMaps: [ // Store map pool for when lobby is confirmed
        'de_dust', 'de_dust2', 'de_inferno', 'de_nuke',
        'de_tuscan', 'de_cpl_strike', 'de_prodigy'
      ],
      bannedMaps: [],
      turn: 'team1', // Start with team1's turn for banning
      teamCaptains: {
        // Store the user ID (database ID) of the captains
        team1: captainTeam1 ? (captainTeam1.user_id || captainTeam1.id) : null,
        team2: captainTeam2 ? (captainTeam2.user_id || captainTeam2.id) : null
      },
      serverCreated: false,
      createdAt: Date.now() // Store creation time for potential cleanup
    };

    // Remove players from queue immediately, but don't assign lobby_id yet
    const playerIds = lobbyPlayers.map(p => p.id);
    await db.query('DELETE FROM queue WHERE player_id IN (?)', [playerIds]);

    console.log(`[Match Ready] Initiating check ${checkId} for ${requiredPlayers} players.`);

    // Emit event to all players in the check to show the popup
    const socketIds = Object.keys(playersForCheck);
    socketIds.forEach(sid => {
      // Using 'redirect' event as planned on client, but could be a new event name
      io.to(sid).emit('redirect', '/lobby.html'); // Client interprets this as "show popup"
    });
    // --- END MATCH READY CHECK ---
  }
}

// -----------------------------------------------------------------------
// SOCKET.IO
// -----------------------------------------------------------------------
io.on('connection', (socket) => {
  // Heartbeat from final-lobby
  socket.on('heartbeat', ({ lobbyId }) => {
    if (lobbies[lobbyId]) {
      lobbies[lobbyId].lastHeartbeat = Date.now();
    }
  });

  // In-game lobby join
  socket.on('joinLobby', async ({ lobbyId, userId }) => {
    socket.join(lobbyId);
    socket.lobbyId = lobbyId;

    if (!lobbies[lobbyId]) {
      lobbies[lobbyId] = {
        availableMaps: [
          'de_dust', 'de_dust2', 'de_inferno', 'de_nuke',
          'de_tuscan', 'de_cpl_strike', 'de_prodigy'
        ],
        bannedMaps: [],
        players: [],
        teams: { team1: [], team2: [] },
        turn: null,
        teamCaptains: {}
      };
    }

    // load players from DB if not present
    if (!lobbies[lobbyId].players || lobbies[lobbyId].players.length === 0) {
      const db = await mysql.createConnection(dbConfigMatchmaking);
      try {
        const [rows] = await db.query('SELECT * FROM players WHERE lobby_id = ?', [lobbyId]);
        lobbies[lobbyId].players = rows || [];
        const teams = { team1: [], team2: [] };
        for (const p of lobbies[lobbyId].players) {
          if (p.team === 'team1') teams.team1.push(p);
          else if (p.team === 'team2') teams.team2.push(p);
        }
        lobbies[lobbyId].teams = teams;
      } catch (err) {
        console.error('Error loading players from DB:', err);
      } finally {
        await db.end();
      }
    }

    // update occupant socket in DB
    const db = await mysql.createConnection(dbConfigMatchmaking);
    try {
      const [pRows] = await db.query(
        'SELECT * FROM players WHERE user_id = ? AND lobby_id = ?',
        [userId, lobbyId]
      );
      if (pRows.length > 0) {
        const occupant = pRows[0];
        await db.query('UPDATE players SET socket_id = ? WHERE id = ?', [socket.id, occupant.id]);
        const memP = lobbies[lobbyId].players.find(pp => pp.id === occupant.id);
        if (memP) memP.socket_id = socket.id;
      }
    } catch (err) {
      console.error('Error updating occupant socket_id:', err);
    } finally {
      await db.end();
    }

    // transform players to add ELO
    const lob = lobbies[lobbyId];
    if (lob && lob.players) {
      const transformed = await Promise.all(
        lob.players.map(async (p) => {
          const dbs = await mysql.createConnection(dbConfigStats);
          const [eloRows] = await dbs.query(
            'SELECT skill FROM ultimate_stats WHERE steamid = ? OR name = ?',
            [p.steam_id || '', p.name || '']
          );
          await dbs.end();
          return {
            ...p,
            profile_picture: p.profile_picture || DEFAULT_PROFILE_PICTURE,
            elo: eloRows[0]?.skill || 0
          };
        })
      );
      socket.emit('lobbyReady', {
        lobbyId,
        players: transformed,
        teams: lob.teams,
        currentTurn: lob.turn
      });
    } else {
      socket.emit('error', 'Lobby not found or no players');
    }
  });

  // Final-lobby chat
  socket.on('publicChatMessage', ({ message, lobbyId }) => {
    const lid = lobbyId || socket.lobbyId;
    const lob = lobbies[lid];
    if (!lob) return;
    const player = lob.players.find(p => p.socket_id === socket.id);
    if (!player) return;

    io.to(lid).emit('publicChatMessage', {
      username: player.name,
      message
    });
  });
  socket.on('teamChatMessage', ({ message, lobbyId }) => {
    const lid = lobbyId || socket.lobbyId;
    const lob = lobbies[lid];
    if (!lob) return;
    const player = lob.players.find(p => p.socket_id === socket.id);
    if (!player) return;
    const team = player.team;
    lob.teams[team].map(p => p.socket_id).forEach(sid => {
      io.to(sid).emit('teamChatMessage', {
        username: player.name,
        message
      });
    });
  });

  // Map ban event
  socket.on('mapSelected', async ({ lobbyId, mapName }) => {
    const lobby = lobbies[lobbyId];
    if (!lobby) return;

    // If no turn started yet, begin with team1
    if (!lobby.turn) {
      lobby.turn = 'team1';
      startCountdown(lobbyId, lobby.turn);
    }

    // occupant check
    const occupant = lobby.players.find(p => p.socket_id === socket.id);
    if (!occupant) return;

    // must be correct captain
    const occupantUserId = occupant.user_id || occupant.id;
    if (lobby.teamCaptains[occupant.team] !== occupantUserId) {
      socket.emit('error', 'Only the captain of your team can ban a map.');
      return;
    }

    // clear timer
    if (banTimers[lobbyId]?.timer) {
      clearTimeout(banTimers[lobbyId].timer);
    }

    // ban
    if (!lobby.bannedMaps.includes(mapName)) {
      lobby.bannedMaps.push(mapName);
      io.to(lobbyId).emit('mapBanned', { mapName });
    }

    // check remain
    const remain = lobby.availableMaps.filter(m => !lobby.bannedMaps.includes(m));
    if (remain.length === 1) {
      // orchestrate
      if (!lobby.serverCreated) {
        lobby.serverCreated = true;
        const finalMap = remain[0];
        const { port, jobName } = await createOrUpdateCsServerJob(lobbyId, finalMap);
        lobby.jobName = jobName;
        io.to(lobbyId).emit('lobbyCreated', {
          serverIp: '192.168.2.69',
          serverPort: port,
          mapName: finalMap
        });
      }
      lobby.turn = null;
      if (banTimers[lobbyId]?.timer) clearTimeout(banTimers[lobbyId].timer);
      return;
    }

    // switch turn
    lobby.turn = (lobby.turn === 'team1') ? 'team2' : 'team1';
    io.to(lobbyId).emit('turnChanged', { currentTurn: lobby.turn });
    startCountdown(lobbyId, lobby.turn);
  });

  // SOLO MATCHMAKING
  socket.on('startMatchmaking', async (user) => {
    // block if in a pre-lobby
    const currentLobbyCode = userPreLobbyMap[socket.id];
    if (currentLobbyCode && preLobbies[currentLobbyCode]) {
      socket.emit('error', 'You are in a pre-lobby. Leave it or start that pre-lobby’s matchmaking.');
      return;
    }

    user.socketId = socket.id;
    const db = await mysql.createConnection(dbConfigMatchmaking);
    try {
      // fetch user row
      let rows;
      if (user.steamId) {
        [rows] = await db.query('SELECT id, status, role FROM users WHERE steam_id = ?', [user.steamId]);
      } else {
        [rows] = await db.query('SELECT id, status, role FROM users WHERE email = ?', [user.email]);
      }
      if (rows.length === 0 || rows[0].status !== 'active') {
        socket.emit('error', 'Your account is not active or not found.');
        return;
      }
      const foundUserId = rows[0].id;

      // see if we already have a players row
      let existingPlayer;
      if (user.steamId) {
        [existingPlayer] = await db.query('SELECT id FROM players WHERE steam_id = ?', [user.steamId]);
      } else {
        [existingPlayer] = await db.query('SELECT id FROM players WHERE email = ?', [user.email]);
      }

      let playerId;
      if (existingPlayer.length > 0) {
        playerId = existingPlayer[0].id;
        await db.query(
          'UPDATE players SET socket_id = ?, user_id = ? WHERE id = ?',
          [socket.id, foundUserId, playerId]
        );
      } else {
        const [insertResult] = await db.query(
          `INSERT INTO players (socket_id, name, profile_picture, steam_id, email, user_id)
           VALUES (?, ?, ?, ?, ?, ?)`,
          [
            socket.id,
            user.username,
            user.profilePictureUrl || DEFAULT_PROFILE_PICTURE,
            user.steamId || null,
            user.email || null,
            foundUserId
          ]
        );
        playerId = insertResult.insertId;
      }

      // check if already in queue
      const [queueRows] = await db.query('SELECT * FROM queue WHERE player_id = ?', [playerId]);
      if (queueRows.length > 0) {
        socket.emit('error', 'You are already in the matchmaking queue.');
        return;
      }

      // insert into queue
      await db.query('INSERT INTO queue (player_id) VALUES (?)', [playerId]);

      // attempt to form a lobby
      const [queue] = await db.query('SELECT * FROM queue');
      const matchmakingQueue = queue.map(q => ({ playerId: q.player_id }));
      await checkQueueAndFormLobby(matchmakingQueue, db);

      socket.emit('queued');
    } catch (err) {
      console.error('Error in startMatchmaking:', err);
      socket.emit('error', 'Server error during matchmaking.');
    } finally {
      await db.end();
    }
  });

  // STOP MATCHMAKING
  socket.on('stopMatchmaking', async () => {
    let db;
    try {
      db = await mysql.createConnection(dbConfigMatchmaking);
      const [players] = await db.query('SELECT * FROM players WHERE socket_id = ?', [socket.id]); // Select * to get group_id
      if (players.length > 0) {
        const player = players[0];
        const playerId = player.id;
        const groupId = player.group_id; // Get the group ID if present

        await db.query('DELETE FROM queue WHERE player_id = ?', [playerId]);

        // If part of a group (pre-lobby), notify the whole group
        if (groupId && groupId.startsWith('group-')) {
           // Find the original invite code associated with this group/leader?
           // This is tricky as the preLobby object is deleted.
           // We might need to pass the inviteCode from the client or find another way.
           // For now, just notify the individual who clicked.
           // A better approach might be needed if group-wide notification is essential here.
           socket.emit('preLobbyQueueStopped'); // Notify the leader who clicked
           // TODO: Consider how to notify other group members if needed.
        } else {
           // Solo queue removal notification
           socket.emit('soloQueueStopped'); // Use a different event for solo
        }
        console.log(`Player ${player.name || playerId} removed from queue.`);
      }
    } catch (err) {
      console.error('Error stopping matchmaking:', err);
      socket.emit('error', 'Error stopping matchmaking queue.');
    } finally {
      if (db) await db.end();
    }
  });

  // CREATE PRE-LOBBY (leader)
  socket.on('createPreLobby', async (user) => { // <-- Add async here
    const existingCode = userPreLobbyMap[socket.id];
    if (existingCode && preLobbies[existingCode]) {
      leavePreLobbyInternal(existingCode, socket.id);
    }

    const inviteCode = generateInviteCode();
    // ensure user has steamId or email for matching
    if (!user.steamId && !user.email) {
      socket.emit('error', 'Cannot create pre-lobby without steamId or email.');
      return;
    }

    // Ensure user has a database ID
    if (!user.id) {
        socket.emit('error', 'Cannot create pre-lobby without user ID.');
        return;
    }

    if (!preLobbies[inviteCode]) {
      preLobbies[inviteCode] = {
        inviteCode,
        leaderSocketId: socket.id, // Keep original socket id for reference if needed
        leaderUserId: user.id,   // Store the leader's database ID
        players: [],
        locked: false
      };
    } else {
      // Update leader IDs if the lobby exists but leader might be re-creating
      preLobbies[inviteCode].leaderSocketId = socket.id;
      preLobbies[inviteCode].leaderUserId = user.id;
    }

    // Fetch skill before adding/updating player
    let skill = 0;
    let dbStats;
    try {
      dbStats = await mysql.createConnection(dbConfigStats);
      skill = await getPlayerSkill(user, dbStats);
    } catch (skillError) {
      console.error("Error connecting to stats DB for skill fetch:", skillError);
    } finally {
      if (dbStats) await dbStats.end();
    }
    user.skill = skill; // Add skill to the user object

    // ensure no duplicates if user tries again
    const existingPlayer = preLobbies[inviteCode].players.find((p) => {
      if (user.steamId && p.steamId === user.steamId) return true;
      if (user.email && p.email === user.email) return true;
      return false;
    });
    if (!existingPlayer) {
      user.socketId = socket.id;
      // Ensure user object includes the id and skill when pushed
      preLobbies[inviteCode].players.push({ ...user, socketId: socket.id }); // user already has .skill
    } else {
      // Update socketId, skill, and potentially other details if user re-creates
      existingPlayer.socketId = socket.id;
      existingPlayer.id = user.id; // Ensure ID is up-to-date
      existingPlayer.username = user.username;
      existingPlayer.profilePictureUrl = user.profilePictureUrl;
      existingPlayer.skill = user.skill; // Update skill
    }

    userPreLobbyMap[socket.id] = inviteCode;
    // Leader ID is already set above (leaderUserId)

    socket.join(`preLobby_${inviteCode}`);
    socket.emit('preLobbyCreated', { inviteCode }); // Client knows it's leader here
    io.to(`preLobby_${inviteCode}`).emit('preLobbyUpdated', {
      inviteCode,
      players: preLobbies[inviteCode].players,
      leaderUserId: preLobbies[inviteCode].leaderUserId // Include leader ID
    });
  });

  // JOIN PRE-LOBBY (guest)
  socket.on('joinPreLobby', async ({ inviteCode, user }) => { // <-- Add async here
    const preLobby = preLobbies[inviteCode];
    if (!preLobby) {
      socket.emit('joinPreLobbyError', { message: 'Invalid invite code.' });
      return;
    }

    // ensure user has steamId or email
    if (!user.steamId && !user.email) {
      socket.emit('joinPreLobbyError', { message: 'Missing both steamId and email, cannot identify user.' });
      return;
    }

    // if user was in another pre-lobby, remove them from there
    const oldCode = userPreLobbyMap[socket.id];
    if (oldCode && preLobbies[oldCode] && oldCode !== inviteCode) {
      leavePreLobbyInternal(oldCode, socket.id);
    }

    if (preLobby.locked) {
      socket.emit('joinPreLobbyError', { message: 'Pre-lobby is locked or has started matchmaking.' });
      return;
    }

    // Fetch skill before adding/updating player
    let skill = 0;
    let dbStats;
    try {
      dbStats = await mysql.createConnection(dbConfigStats);
      skill = await getPlayerSkill(user, dbStats);
    } catch (skillError) {
      console.error("Error connecting to stats DB for skill fetch:", skillError);
    } finally {
      if (dbStats) await dbStats.end();
    }
    user.skill = skill; // Add skill to the user object

    // find or push
    const existingPlayer = preLobby.players.find((p) => {
      if (user.steamId && p.steamId === user.steamId) return true;
      if (user.email && p.email === user.email) return true;
      return false;
    });
    if (!existingPlayer) {
      user.socketId = socket.id;
      // Ensure user object includes the id and skill when pushed
      preLobby.players.push({ ...user, socketId: socket.id }); // user already has .skill
    } else {
      // Update socketId and skill if user rejoins
      existingPlayer.socketId = socket.id;
      existingPlayer.id = user.id; // Ensure ID is up-to-date
      existingPlayer.skill = user.skill; // Update skill
    }

    userPreLobbyMap[socket.id] = inviteCode;
    socket.join(`preLobby_${inviteCode}`);

    socket.emit('preLobbyJoined', {
      inviteCode,
      inviteCode,
      players: preLobby.players
    }); // Client knows it's not leader here
    io.to(`preLobby_${inviteCode}`).emit('preLobbyUpdated', {
      inviteCode,
      players: preLobby.players,
      leaderUserId: preLobby.leaderUserId // Include leader ID
    });
  });

  // get PreLobby players
  socket.on('getPreLobbyPlayers', ({ inviteCode }) => {
    const preLobby = preLobbies[inviteCode];
    if (!preLobby) {
      socket.emit('joinPreLobbyError', { message: 'Pre-lobby not found.' });
      return;
    }
    socket.emit('preLobbyPlayers', {
      inviteCode,
      players: preLobby.players,
      leaderUserId: preLobby.leaderUserId // Include leader ID
    });
  });

  // rejoin PreLobby (restore UI state)
  socket.on('rejoinPreLobby', ({ inviteCode }) => {
    const preLobby = preLobbies[inviteCode];
    if (!preLobby) {
      socket.emit('joinPreLobbyError', { message: 'Pre-lobby not found.' });
      return;
    }
    socket.join(`preLobby_${inviteCode}`);
    socket.emit('preLobbyRestored', {
      inviteCode,
      players: preLobby.players,
      leaderUserId: preLobby.leaderUserId // Include leader ID
    });
  });

  // START PRE-LOBBY MATCHMAKING
  socket.on('startPreLobbyMatchmaking', async ({ inviteCode }) => {
    const preLobby = preLobbies[inviteCode];
    if (!preLobby) {
      socket.emit('error', 'Pre-lobby not found.');
      return;
    }

    // --- DEBUGGING ---
    console.log(`[StartPreLobby] Request from socket: ${socket.id}`);
    console.log(`[StartPreLobby] Checking lobby: ${inviteCode}`);
    console.log(`[StartPreLobby] Full preLobby object: ${JSON.stringify(preLobby, null, 2)}`);
    // --- END DEBUGGING ---

    // Find the user making the request by their current socket.id
    const requestingPlayer = preLobby.players.find(p => p.socketId === socket.id);

    // Verify the player was found and their ID matches the stored leader ID
    if (!requestingPlayer) {
      console.error(`[StartPreLobby Error] Player not found for socket ${socket.id} in lobby ${inviteCode}`);
      socket.emit('error', 'Could not identify you in the pre-lobby.');
      return;
    }

    // Compare IDs as strings to avoid type mismatches (e.g., number vs string)
    if (String(requestingPlayer.id) !== String(preLobby.leaderUserId)) {
      console.error(`[StartPreLobby Error] Requester ID ${requestingPlayer.id} (type: ${typeof requestingPlayer.id}) does not match Leader ID ${preLobby.leaderUserId} (type: ${typeof preLobby.leaderUserId}) for lobby ${inviteCode}`);
      socket.emit('error', 'Only the lobby leader can start matchmaking.');
      return;
    }

    console.log(`[StartPreLobby] Leader check passed for User ID: ${requestingPlayer.id}`);
    preLobby.locked = true;

    const groupId = generateUniqueName('group');
    const db = await mysql.createConnection(dbConfigMatchmaking);
    try {
      const playerIds = [];
      for (const u of preLobby.players) {
        const profilePic = u.profilePictureUrl || DEFAULT_PROFILE_PICTURE;
        let existingPlayer;
        if (u.steamId) {
          [existingPlayer] = await db.query('SELECT id FROM players WHERE steam_id = ?', [u.steamId]);
        } else {
          [existingPlayer] = await db.query('SELECT id FROM players WHERE email = ?', [u.email]);
        }
        let playerId;
        if (existingPlayer && existingPlayer.length > 0) {
          playerId = existingPlayer[0].id;
          await db.query(
            'UPDATE players SET socket_id = ?, group_id = ? WHERE id = ?',
            [u.socketId, groupId, playerId]
          );
        } else {
          const [insertResult] = await db.query(
            `INSERT INTO players
             (socket_id, name, profile_picture, group_id, steam_id, email)
             VALUES (?, ?, ?, ?, ?, ?)`,
            [
              u.socketId,
              u.username,
              profilePic,
              groupId,
              u.steamId || null,
              u.email || null
            ]
          );
          playerId = insertResult.insertId;
        }
        playerIds.push(playerId);
        // also add them to queue if they're not already
        const [queueRows] = await db.query('SELECT * FROM queue WHERE player_id = ?', [playerId]);
        if (queueRows.length === 0) {
          await db.query('INSERT INTO queue (player_id) VALUES (?)', [playerId]);
        }
      }

      // remove the entire pre-lobby so no duplicates remain
      delete preLobbies[inviteCode];
      preLobby.players.forEach(u => {
        delete userPreLobbyMap[u.socketId];
      });

      // now see if we can match them
      const [queue] = await db.query('SELECT * FROM queue');
      const matchmakingQueue = queue.map(q => ({ playerId: q.player_id }));
      await checkQueueAndFormLobby(matchmakingQueue, db);

      // Let everyone in the pre-lobby know they are queued
      io.to(`preLobby_${inviteCode}`).emit('preLobbyQueued', { groupId });

    } catch (error) {
      console.error('Error in startPreLobbyMatchmaking:', error);
      socket.emit('error', 'Error starting pre-lobby matchmaking.');
      preLobby.locked = false;
    } finally {
      await db.end();
    }
  });

  // LEAVE PRE-LOBBY
  socket.on('leavePreLobby', ({ inviteCode }) => {
    if (!inviteCode) return;
    if (!preLobbies[inviteCode]) return;
    leavePreLobbyInternal(inviteCode, socket.id);
  });

  // KICK FROM PRE-LOBBY
  socket.on('kickFromPreLobby', (targetSocketId) => {
    const inviteCode = userPreLobbyMap[socket.id];
    if (!inviteCode || !preLobbies[inviteCode]) return;
    const preLobby = preLobbies[inviteCode];

    // Find the user making the request by their current socket.id
    const requestingPlayer = preLobby.players.find(p => p.socketId === socket.id);

    // Check if the requesting user's database ID matches the stored leader's database ID
    if (!requestingPlayer || String(requestingPlayer.id) !== String(preLobby.leaderUserId)) {
      socket.emit('error', 'Only the lobby leader can kick players.');
      return;
    }
    // Leader check passed, proceed to kick the target
    leavePreLobbyInternal(inviteCode, targetSocketId, true);
  });

  // Pre-lobby chat
  socket.on('preLobbyChatMessage', ({ message, inviteCode }) => {
    if (!inviteCode || !preLobbies[inviteCode]) return;
    const preLobby = preLobbies[inviteCode];
    const player = preLobby.players.find(p => p.socketId === socket.id);
    if (!player) return;
    io.to(`preLobby_${inviteCode}`).emit('preLobbyChatMessage', {
      username: player.username,
      message,
      profilePictureUrl: player.profilePictureUrl || DEFAULT_PROFILE_PICTURE
    });
  });

  // ================================
  // MATCH READY CHECK-IN HANDLERS
  // ================================
  socket.on('confirmMatchReady', async () => {
    const checkId = Object.keys(matchReadyChecks).find(id => matchReadyChecks[id].players[socket.id]);
    if (!checkId || !matchReadyChecks[checkId]) {
      console.warn(`[Match Ready] Received confirmMatchReady from socket ${socket.id} but no active check found.`);
      return;
    }

    const check = matchReadyChecks[checkId];
    if (check.players[socket.id]) {
      check.players[socket.id].accepted = true;
      console.log(`[Match Ready] Player ${check.players[socket.id].userId} (socket ${socket.id}) accepted check ${checkId}.`);

      const acceptedCount = Object.values(check.players).filter(p => p.accepted).length;

      // Broadcast update
      Object.keys(check.players).forEach(sid => {
        io.to(sid).emit('matchReadyCheckUpdate', {
          acceptedCount,
          totalPlayers: check.totalPlayers
        });
      });

      // Check if all accepted
      if (acceptedCount === check.totalPlayers) {
        console.log(`[Match Ready] All players accepted for check ${checkId}. Confirming match.`);
        clearTimeout(check.timer); // Stop the timeout timer
        await confirmMatchFormation(checkId); // Finalize lobby creation
        delete matchReadyChecks[checkId]; // Clean up the check entry
      }
    }
  });

  async function confirmMatchFormation(checkId) {
    const check = matchReadyChecks[checkId];
    if (!check) return; // Should not happen, but safety check

    const lobbyId = check.lobbyId;
    const lobbyPlayers = Object.values(check.players).map(p => p.playerData); // Get the stored player data

    // Create the actual lobby entry
    lobbies[lobbyId] = {
      players: lobbyPlayers,
      teams: check.teams,
      availableMaps: check.availableMaps,
      bannedMaps: [],
      turn: 'team1', // Start map ban phase
      teamCaptains: check.captains,
      serverCreated: false,
      createdAt: check.createdAt || Date.now() // Use stored time or now
    };

    // Update database: Assign lobby_id and team
    let db;
    try {
      db = await mysql.createConnection(dbConfigMatchmaking);
      for (const player of lobbyPlayers) {
        await db.query(
          'UPDATE players SET lobby_id = ?, team = ? WHERE id = ?',
          [lobbyId, player.team, player.id] // player.team should be set during check creation
        );
      }
      console.log(`[Match Ready] Database updated for lobby ${lobbyId}.`);
    } catch (dbError) {
      console.error(`[Match Ready] Error updating database for confirmed lobby ${lobbyId}:`, dbError);
      // Handle potential DB error - maybe try to rollback or notify players?
    } finally {
      if (db) await db.end();
    }

    // Notify players that the match is confirmed and redirect to lobby page
    Object.keys(check.players).forEach(sid => {
      io.to(sid).emit('matchReadyConfirmed'); // Client handles redirect on this event
    });

    // Start the map ban countdown for the newly created lobby
    startCountdown(lobbyId, 'team1');
  }

  async function handleMatchReadyTimeout(checkId) {
    const check = matchReadyChecks[checkId];
    if (!check) return; // Already handled or cleaned up

    console.log(`[Match Ready] Check ${checkId} timed out.`);

    // Notify all players in the check about the failure
    Object.keys(check.players).forEach(sid => {
      io.to(sid).emit('matchReadyCheckFailed', { reason: 'Match timed out. Not all players accepted.' });
    });

    // Re-queue players who *did* accept (optional, depends on desired logic)
    // For simplicity now, we just fail the match formation.
    // If re-queuing: Need to add players back to the 'queue' table.
    // const acceptedPlayers = Object.values(check.players).filter(p => p.accepted);
    // if (acceptedPlayers.length > 0) {
    //   // Add logic to re-insert acceptedPlayers into the queue table
    // }

    // Clean up the check entry
    delete matchReadyChecks[checkId];
  }

  async function handleMatchReadyDisconnect(socketId) {
      const checkId = Object.keys(matchReadyChecks).find(id => matchReadyChecks[id].players[socketId]);
      if (!checkId || !matchReadyChecks[checkId]) {
          return; // Player wasn't in an active check
      }

      const check = matchReadyChecks[checkId];
      console.log(`[Match Ready] Player ${check.players[socketId]?.userId} (socket ${socketId}) disconnected during check ${checkId}. Failing check.`);

      clearTimeout(check.timer); // Stop the timeout

      // Notify remaining players
      Object.keys(check.players).forEach(sid => {
          if (sid !== socketId) { // Don't notify the disconnected player
              io.to(sid).emit('matchReadyCheckFailed', { reason: 'A player disconnected during the ready check.' });
          }
      });

      // Clean up the check entry
      delete matchReadyChecks[checkId];

      // Optional: Re-queue remaining players? Similar logic to timeout.
  }


  // On disconnect
  socket.on('disconnect', async () => {
    console.log(`Socket ${socket.id} disconnected.`);
    await handleMatchReadyDisconnect(socket.id); // Handle disconnect during ready check
    const inviteCode = userPreLobbyMap[socket.id];
    if (inviteCode) {
      leavePreLobbyInternal(inviteCode, socket.id);
    }

    let db;
    try {
      db = await mysql.createConnection(dbConfigMatchmaking);
      const [players] = await db.query('SELECT * FROM players WHERE socket_id = ?', [socket.id]);
      if (players.length > 0) {
        const player = players[0];
        // remove them from queue
        await db.query('DELETE FROM queue WHERE player_id = ?', [player.id]);
        console.log(`Player ${player.name} removed from queue.`);

        // handle final-lobby cleanup
        const lobbyId = socket.lobbyId;
        if (lobbyId && lobbies[lobbyId]) {
          const lob = lobbies[lobbyId];
          lob.players = lob.players.filter(p => p.socket_id !== socket.id);

          if (lob.players.length === 0) {
            if (banTimers[lobbyId]) {
              clearTimeout(banTimers[lobbyId].timer);
              delete banTimers[lobbyId];
            }
            if (!lob.serverCreated && lob.jobName) {
              try {
                await k8sBatchApi.deleteNamespacedJob(lob.jobName, 'default');
                console.log(`Deleted abandoned job: ${lob.jobName}`);
              } catch (error) {
                console.error('Error deleting pre-server job:', error.body || error);
              }
            }
            delete lobbies[lobbyId];
            console.log(`Lobby ${lobbyId} cleaned up.`);
          }
        }
      }
    } catch (error) {
      console.error('Error on disconnect:', error);
    } finally {
      if (db) await db.end();
    }
  });
});

// Attach routes
appRoutes();

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
