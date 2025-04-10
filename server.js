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
    res.json({
      id: user.id,
      username: user.username,
      steamId: user.steamId || null,
      email: user.email || null,
      profilePictureUrl: user.profile_picture || DEFAULT_PROFILE_PICTURE
    });
  });

  app.get('/user/skill', ensureAuthenticated, async (req, res) => {
    const user = req.user;
    const db = await mysql.createConnection(dbConfigStats);
    try {
      const [rows] = await db.query(
        `SELECT skill FROM ultimate_stats
         WHERE steamid = ? OR name = ?`,
        [user.steamId || '', user.username || '']
      );
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
    if (preLobby.leader === socketId) {
      if (preLobby.players.length > 0) {
        preLobby.leader = preLobby.players[0].socketId;
      } else {
        delete preLobbies[inviteCode];
        return;
      }
    }

    // broadcast updated list
    io.to(`preLobby_${inviteCode}`).emit('preLobbyUpdated', {
      inviteCode,
      players: preLobby.players
    });
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

    for (let i = 0; i < lobbyPlayers.length; i++) {
      if (i % 2 === 0) {
        team1.push(lobbyPlayers[i]);
        lobbyPlayers[i].team = 'team1';
      } else {
        team2.push(lobbyPlayers[i]);
        lobbyPlayers[i].team = 'team2';
      }
    }

    // designate captains
    function designateCaptain(team) {
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
    team1.forEach(p => p.captain = false);
    team2.forEach(p => p.captain = false);
    captainTeam1.captain = true;
    captainTeam2.captain = true;

    // store final-lobby info in memory
    lobbies[lobbyId] = {
      players: lobbyPlayers,
      teams: { team1, team2 },
      availableMaps: [
        'de_dust', 'de_dust2', 'de_inferno', 'de_nuke',
        'de_tuscan', 'de_cpl_strike', 'de_prodigy'
      ],
      bannedMaps: [],
      turn: 'team1',
      teamCaptains: {
        team1: captainTeam1.user_id || captainTeam1.id,
        team2: captainTeam2.user_id || captainTeam2.id
      },
      serverCreated: false,
      createdAt: Date.now()
    };

    // mark DB players as assigned
    const playerIds = lobbyPlayers.map(p => p.id);
    for (let p of lobbyPlayers) {
      await db.query(
        'UPDATE players SET lobby_id = ?, team = ? WHERE id = ?',
        [lobbyId, p.team, p.id]
      );
    }
    await db.query('DELETE FROM queue WHERE player_id IN (?)', [playerIds]);

    // Let them know it's time for map banning
    io.to(lobbyId).emit('turnChanged', { currentTurn: 'team1' });

    // redirect each occupant to /lobby
    const socketIds = lobbyPlayers.map(p => p.socket_id);
    socketIds.forEach(sid => {
      io.to(sid).emit('redirect', `/lobby.html?lobbyId=${lobbyId}`);
    });
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
      const [players] = await db.query('SELECT id FROM players WHERE socket_id = ?', [socket.id]);
      if (players.length > 0) {
        await db.query('DELETE FROM queue WHERE player_id = ?', [players[0].id]);
        socket.emit('error', 'You have been removed from the matchmaking queue.');
      }
    } catch (err) {
      console.error('Error stopping matchmaking:', err);
      socket.emit('error', 'Error stopping matchmaking queue.');
    } finally {
      if (db) await db.end();
    }
  });

  // CREATE PRE-LOBBY (leader)
  socket.on('createPreLobby', (user) => {
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

    // ensure no duplicates if user tries again
    const existingPlayer = preLobbies[inviteCode].players.find((p) => {
      if (user.steamId && p.steamId === user.steamId) return true;
      if (user.email && p.email === user.email) return true;
      return false;
    });
    if (!existingPlayer) {
      user.socketId = socket.id;
      // Ensure user object includes the id when pushed
      preLobbies[inviteCode].players.push({ ...user, socketId: socket.id });
    } else {
      // Update socketId and potentially other details if user re-creates
      existingPlayer.socketId = socket.id;
      existingPlayer.id = user.id; // Ensure ID is up-to-date
      existingPlayer.username = user.username;
      existingPlayer.profilePictureUrl = user.profilePictureUrl;
    }

    userPreLobbyMap[socket.id] = inviteCode;
    // Leader ID is already set above (leaderUserId)

    socket.join(`preLobby_${inviteCode}`);
    socket.emit('preLobbyCreated', { inviteCode });
    io.to(`preLobby_${inviteCode}`).emit('preLobbyUpdated', {
      inviteCode,
      players: preLobbies[inviteCode].players
    });
  });

  // JOIN PRE-LOBBY (guest)
  socket.on('joinPreLobby', ({ inviteCode, user }) => {
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

    // find or push
    const existingPlayer = preLobby.players.find((p) => {
      if (user.steamId && p.steamId === user.steamId) return true;
      if (user.email && p.email === user.email) return true;
      return false;
    });
    if (!existingPlayer) {
      user.socketId = socket.id;
      // Ensure user object includes the id when pushed
      preLobby.players.push({ ...user, socketId: socket.id });
    } else {
      // Update socketId if user rejoins
      existingPlayer.socketId = socket.id;
      existingPlayer.id = user.id; // Ensure ID is up-to-date
    }

    userPreLobbyMap[socket.id] = inviteCode;
    socket.join(`preLobby_${inviteCode}`);

    socket.emit('preLobbyJoined', {
      inviteCode,
      players: preLobby.players
    });
    io.to(`preLobby_${inviteCode}`).emit('preLobbyUpdated', {
      inviteCode,
      players: preLobby.players
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
      players: preLobby.players
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
      players: preLobby.players
    });
  });

  // START PRE-LOBBY MATCHMAKING
  socket.on('startPreLobbyMatchmaking', async ({ inviteCode }) => {
    const preLobby = preLobbies[inviteCode];
    if (!preLobby) {
      socket.emit('error', 'Pre-lobby not found.');
      return;
    }

    // Find the user making the request by their current socket.id
    const requestingPlayer = preLobby.players.find(p => p.socketId === socket.id);

    // Check if the requesting user's database ID matches the stored leader's database ID
    if (!requestingPlayer || requestingPlayer.id !== preLobby.leaderUserId) {
      socket.emit('error', 'Only the lobby leader can start matchmaking.');
      return;
    }
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

      // let them know they are queued
      preLobby.players.forEach(u => {
        if (u.socketId) {
          io.to(u.socketId).emit('queued', { groupId });
        }
      });
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
    if (preLobby.leader !== socket.id) {
      socket.emit('error', 'Only the lobby leader can kick players.');
      return;
    }
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

  // On disconnect
  socket.on('disconnect', async () => {
    console.log(`Socket ${socket.id} disconnected.`);
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
