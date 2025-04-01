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

// Read captain configuration from captains.json
let captainConfig = { steamIds: [], emails: [] };
try {
  const configPath = path.join(__dirname, 'captains.json');
  const configData = fs.readFileSync(configPath, 'utf8');
  captainConfig = JSON.parse(configData);
} catch (err) {
  console.error("Error reading captain configuration:", err);
}

// Server cleanup configuration
const MAX_SERVER_AGE = 7200000; // 2 hours in milliseconds

// Update the fallback image to use a local file that exists in your public directory.
const DEFAULT_PROFILE_PICTURE = '/img/fallback-pfp.png';

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Kubernetes client
const kc = new KubeConfig();
kc.loadFromDefault();
const k8sBatchApi = kc.makeApiClient(BatchV1Api);

const PORT = 3000;

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

app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false
}));
app.use(bodyParser.urlencoded({ extended: false }));

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
      const [insertResult] = await db.query(
        'INSERT INTO users (username, steam_id, profile_picture, role, status, password_hash) VALUES (?, ?, ?, ?, ?, ?)',
        [profile.username, profile.steamId, profile.photos[0].value, 'user', 'active', '']
      );
      const userId = insertResult.insertId;
      const dbStats = await mysql.createConnection(dbConfigStats);
      await dbStats.query('INSERT INTO ultimate_stats (steamid, skill) VALUES (?, ?)', [profile.steamId, 1000]);
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
      'INSERT INTO users (username, email, password_hash, role, status) VALUES (?, ?, ?, ?, ?)',
      [username, email, passwordHash, 'user', 'active']
    );
    const userId = result.insertId;
    const dbStats = await mysql.createConnection(dbConfigStats);
    await dbStats.query('INSERT INTO ultimate_stats (steamid, skill) VALUES (?, ?)', [email, 1000]);
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
  const playerName = user.username;
  const db = await mysql.createConnection(dbConfigStats);
  try {
    const [rows] = await db.query('SELECT skill FROM ultimate_stats WHERE name = ?', [playerName]);
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
    await db.query('UPDATE users SET status = ?, role = ? WHERE id = ?', [status, role, userId]);
    await db.end();
    res.json({ success: true });
  } catch (err) {
    console.error('Error updating user:', err);
    res.status(500).json({ error: 'Database error' });
  }
});

// ----------------------------------------------------------
// Lobby & Pre-Lobby Data
// ----------------------------------------------------------
let lobbies = {};
let preLobbies = {};
let banTimers = {};  // For countdown timers during map banning

// ----------------------------------------------------------
// Helper functions for map ban countdown
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
  const remainingMaps = lobby.availableMaps.filter(m => !lobby.bannedMaps.includes(m));
  if (remainingMaps.length === 0) return;
  const autoBannedMap = remainingMaps[0];
  lobby.bannedMaps.push(autoBannedMap);
  io.to(lobbyId).emit('mapBanned', { mapName: autoBannedMap });
  
  const newRemaining = lobby.availableMaps.filter(m => !lobby.bannedMaps.includes(m));
  if (newRemaining.length === 1) {
    if (!lobby.serverCreated) {
      lobby.serverCreated = true;
      const finalMap = newRemaining[0];
      const { port, jobName } = await createOrUpdateCsServerJob(lobbyId, finalMap);
      lobby.jobName = jobName;
      io.to(lobbyId).emit('lobbyCreated', {
        serverIp: '192.168.2.69',
        serverPort: port,
        mapName: finalMap
      });
      lobby.turn = null;
      if (banTimers[lobbyId] && banTimers[lobbyId].timer) {
        clearTimeout(banTimers[lobbyId].timer);
      }
    }
    return;
  }
  // Switch turn and restart countdown
  lobby.turn = lobby.turn === 'team1' ? 'team2' : 'team1';
  io.to(lobbyId).emit('turnChanged', { currentTurn: lobby.turn });
  startCountdown(lobbyId, lobby.turn);
}

// ----------------------------------------------------------
// Socket.io
// ----------------------------------------------------------
io.on('connection', (socket) => {
  // Heartbeat handler for connection tracking
  socket.on('heartbeat', ({ lobbyId }) => {
    if (lobbies[lobbyId]) {
      lobbies[lobbyId].lastHeartbeat = Date.now();
    }
  });
  // joinLobby
  socket.on('joinLobby', async ({ lobbyId, userId }) => {
    socket.join(lobbyId);
    socket.lobbyId = lobbyId;
    socket.lobbyId = lobbyId;
    if (!lobbies[lobbyId]) {
      lobbies[lobbyId] = {
        availableMaps: ['de_dust', 'de_dust2', 'de_inferno', 'de_nuke', 'de_tuscan', 'de_cpl_strike', 'de_prodigy'],
        bannedMaps: [],
        players: [],
        teams: { team1: [], team2: [] },
        turn: null,
        teamCaptains: {}
      };
    }
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
    const db = await mysql.createConnection(dbConfigMatchmaking);
    try {
      const [pRows] = await db.query(
        'SELECT * FROM players WHERE user_id = ? AND lobby_id = ?',
        [userId, lobbyId]
      );
      if (pRows.length > 0) {
        const occupant = pRows[0];
        await db.query('UPDATE players SET socket_id = ? WHERE id = ?', [socket.id, occupant.id]);
        const memP = lobbies[lobbyId].players.find(p => p.id === occupant.id);
        if (memP) memP.socket_id = socket.id;
      }
    } catch (err) {
      console.error('Error updating occupant socket_id:', err);
    } finally {
      await db.end();
    }
    const lobby = lobbies[lobbyId];
    if (lobby && lobby.players) {
      // Transform player data and ensure fallback image is used if needed.
      const transformedPlayers = await Promise.all(lobby.players.map(async (p) => {
        // Fetch fresh ELO data from stats DB for each player
        const dbStats = await mysql.createConnection(dbConfigStats);
        const [eloRows] = await dbStats.query(
          'SELECT skill FROM ultimate_stats WHERE steamid = ? OR name = ?',
          [p.steam_id, p.email]
        );
        await dbStats.end();

        return {
          user_id: p.user_id,
          id: p.id,
          name: p.name,
          profile_picture: p.profile_picture || DEFAULT_PROFILE_PICTURE,
          team: p.team,
          steam_id: p.steam_id,
          email: p.email,
          elo: eloRows[0]?.skill || 1000 // Use actual ELO value
        };
      }));
      socket.emit('lobbyReady', {
        lobbyId,
        players: transformedPlayers,
        teams: lobby.teams,
        currentTurn: lobby.turn
      });
    } else {
      socket.emit('error', 'Lobby not found or no players');
    }
  });
  // Public chat
  socket.on('publicChatMessage', ({ message, lobbyId }) => {
    const finalLobbyId = lobbyId || socket.lobbyId;
    if (!finalLobbyId || !lobbies[finalLobbyId]) return;
    const player = lobbies[finalLobbyId].players.find(p => p.socket_id === socket.id);
    if (!player) return;
    io.to(finalLobbyId).emit('publicChatMessage', {
      username: player.name,
      message
    });
  });
  // Team chat
  socket.on('teamChatMessage', ({ message, lobbyId }) => {
    const finalLobbyId = lobbyId || socket.lobbyId;
    if (!finalLobbyId || !lobbies[finalLobbyId]) return;
    const player = lobbies[finalLobbyId].players.find(p => p.socket_id === socket.id);
    if (!player) return;
    const team = player.team;
    const teamSockets = lobbies[finalLobbyId].teams[team].map(p => p.socket_id);
    teamSockets.forEach(sid => {
      io.to(sid).emit('teamChatMessage', {
        username: player.name,
        message
      });
    });
  });
  // Start Matchmaking
  socket.on('startMatchmaking', async (user) => {
    user.socketId = socket.id;
    const db = await mysql.createConnection(dbConfigMatchmaking);
    try {
      let rows;
      if (user.steamId) {
        [rows] = await db.query('SELECT id, status, role FROM users WHERE steam_id = ?', [user.steamId]);
      } else {
        [rows] = await db.query('SELECT id, status, role FROM users WHERE email = ?', [user.email]);
      }
      if (rows.length === 0 || rows[0].status !== 'active') {
        socket.emit('error', 'Your account is not active.');
        return;
      }
      const foundUserId = rows[0].id;
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
          'INSERT INTO players (socket_id, name, profile_picture, steam_id, email, user_id) VALUES (?, ?, ?, ?, ?, ?)',
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
      const [queueRows] = await db.query('SELECT * FROM queue WHERE player_id = ?', [playerId]);
      if (queueRows.length > 0) {
        socket.emit('error', 'You are already in the matchmaking queue.');
        return;
      }
      await db.query('INSERT INTO queue (player_id) VALUES (?)', [playerId]);
      const [queue] = await db.query('SELECT * FROM queue');
      const matchmakingQueue = queue.map(q => ({ playerId: q.player_id }));
      await checkQueueAndFormLobby(matchmakingQueue, db);
    } catch (err) {
      console.error('Error interacting with DB:', err);
      socket.emit('error', 'Server error during matchmaking.');
    } finally {
      await db.end();
    }
  });
  // Pre-lobby
  socket.on('createPreLobby', (user) => {
    const inviteCode = generateInviteCode();
    const preLobby = {
      inviteCode,
      leader: user,
      players: [user]
    };
    preLobbies[inviteCode] = preLobby;
    socket.join(`preLobby_${inviteCode}`);
    socket.emit('preLobbyCreated', { inviteCode });
  });
  socket.on('joinPreLobby', ({ inviteCode, user }) => {
    const preLobby = preLobbies[inviteCode];
    if (!preLobby) {
      socket.emit('error', 'Invalid invite code.');
      return;
    }
    user.socketId = socket.id;
    preLobby.players.push(user);
    socket.join(`preLobby_${inviteCode}`);
    io.to(`preLobby_${inviteCode}`).emit('preLobbyUpdated', { players: preLobby.players });
  });
  socket.on('startPreLobbyMatchmaking', async ({ inviteCode }) => {
    const preLobby = preLobbies[inviteCode];
    if (!preLobby) {
      socket.emit('error', 'Pre-lobby not found.');
      return;
    }
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
        if (existingPlayer.length > 0) {
          playerId = existingPlayer[0].id;
          await db.query('UPDATE players SET socket_id = ?, group_id = ? WHERE id = ?', [u.socketId, groupId, playerId]);
        } else {
          const [insertResult] = await db.query(
            'INSERT INTO players (socket_id, name, profile_picture, group_id, steam_id, email) VALUES (?, ?, ?, ?, ?, ?)',
            [u.socketId, u.username, profilePic, groupId, u.steamId || null, u.email || null]
          );
          playerId = insertResult.insertId;
        }
        playerIds.push(playerId);
        await db.query('INSERT INTO queue (player_id) VALUES (?)', [playerId]);
      }
      delete preLobbies[inviteCode];
      const [queue] = await db.query('SELECT * FROM queue');
      const matchmakingQueue = queue.map(q => ({ playerId: q.player_id }));
      await checkQueueAndFormLobby(matchmakingQueue, db);
    } catch (error) {
      console.error('Error in startPreLobbyMatchmaking:', error);
    } finally {
      await db.end();
    }
  });
  // ----------------------------------------------------------
  // Main Matchmaking Logic
  // ----------------------------------------------------------
  async function checkQueueAndFormLobby(matchmakingQueue, db) {
    const groupedPlayers = {};
    for (const queued of matchmakingQueue) {
      const [playerData] = await db.query('SELECT * FROM players WHERE id = ?', [queued.playerId]);
      
      // Add ELO fetch from stats database
      const dbStats = await mysql.createConnection(dbConfigStats);
      const [eloRows] = await dbStats.query('SELECT skill FROM ultimate_stats WHERE steamid = ? OR name = ?', 
        [playerData[0].steam_id, playerData[0].email]);
      await dbStats.end();
      
      // Create player object with ELO
      const playerWithElo = {
        ...playerData[0],
        elo: eloRows[0]?.skill || 1000
      };
      
      const groupId = playerWithElo.group_id || `solo_${playerWithElo.id}`;
      if (!groupedPlayers[groupId]) groupedPlayers[groupId] = [];
      groupedPlayers[groupId].push(playerWithElo); // Push the playerWithElo object instead
    }
    // For normal use, set requiredPlayers to an even number (e.g., 10)
    const requiredPlayers = 2;
    const groups = Object.values(groupedPlayers);
    let lobbyPlayers = [];
    while (groups.length > 0 && lobbyPlayers.length < requiredPlayers) {
      const group = groups.shift();
      if (lobbyPlayers.length + group.length <= requiredPlayers) {
        lobbyPlayers = lobbyPlayers.concat(group);
      } else {
        groups.push(group);
        break;
      }
    }
    if (lobbyPlayers.length === requiredPlayers) {
      const lobbyId = generateUniqueName('lobby');
      const team1 = [];
      const team2 = [];
      // Evenly distribute players across two teams
      for (let i = 0; i < lobbyPlayers.length; i++) {
        if (i % 2 === 0) {
          team1.push(lobbyPlayers[i]);
          lobbyPlayers[i].team = 'team1';
        } else {
          team2.push(lobbyPlayers[i]);
          lobbyPlayers[i].team = 'team2';
        }
      }
      // Designate captain with priority:
      // For each team, check for a player whose steamId (or steam_id) or email matches the captainConfig.
      // If none match, choose the first player.
      function designateCaptain(team) {
        const priorityCandidate = team.find(p => {
          const sid = p.steam_id || p.steamId; // check both possible keys
          if (sid && captainConfig.steamIds.includes(sid)) return true;
          if (p.email && captainConfig.emails.includes(p.email)) return true;
          return false;
        });
        return priorityCandidate || team[0];
      }
      const captainTeam1 = designateCaptain(team1);
      const captainTeam2 = designateCaptain(team2);
      // Mark only these players as captains
      team1.forEach(p => p.captain = false);
      team2.forEach(p => p.captain = false);
      captainTeam1.captain = true;
      captainTeam2.captain = true;
      const teamCaptains = {
        team1: captainTeam1.user_id || captainTeam1.id,
        team2: captainTeam2.user_id || captainTeam2.id
      };
      lobbies[lobbyId] = {
        players: lobbyPlayers,
        teams: { team1, team2 },
        availableMaps: ['de_dust', 'de_dust2', 'de_inferno', 'de_nuke', 'de_tuscan', 'de_cpl_strike', 'de_prodigy'],
        bannedMaps: [],
        turn: 'team1', // Set initial turn to team1
        teamCaptains,
        serverCreated: false,
        createdAt: Date.now()
      };
      const playerIds = lobbyPlayers.map(p => p.id);
      // Update DB with the assigned team for each player
      for (let p of lobbyPlayers) {
        await db.query('UPDATE players SET lobby_id = ?, team = ? WHERE id = ?', [lobbyId, p.team, p.id]);
      }
      // Remove them from the queue
      await db.query('DELETE FROM queue WHERE player_id IN (?)', [playerIds]);
      // Emit initial turn info so that clients know which team is active
      io.to(lobbyId).emit('turnChanged', { currentTurn: 'team1' });
      // Redirect players to the new lobby
      const socketIds = lobbyPlayers.map(p => p.socket_id);
      socketIds.forEach(sid => {
        io.to(sid).emit('redirect', `/lobby.html?lobbyId=${lobbyId}`);
      });
    }
  }
  // Map selection with alternating bans and countdown timer
  socket.on('mapSelected', async ({ lobbyId, mapName }) => {
    const lobby = lobbies[lobbyId];
    if (!lobby) return;
    if (!lobby.turn) {
      lobby.turn = 'team1';
      startCountdown(lobbyId, lobby.turn);
    }
    const player = lobby.players.find(p => p.socket_id === socket.id);
    if (!player || player.team !== lobby.turn) return;
    // Check if the player is the designated captain for their team
    const teamCaptain = lobby.teamCaptains[player.team];
    const playerUserId = player.user_id || player.id;
    if (playerUserId !== teamCaptain) {
      socket.emit('error', 'Only your team captain can ban a map.');
      return;
    }
    if (banTimers[lobbyId] && banTimers[lobbyId].timer) {
      clearTimeout(banTimers[lobbyId].timer);
    }
    if (!lobby.bannedMaps.includes(mapName)) {
      lobby.bannedMaps.push(mapName);
      io.to(lobbyId).emit('mapBanned', { mapName });
    }
    const remainingMaps = lobby.availableMaps.filter(m => !lobby.bannedMaps.includes(m));
    if (remainingMaps.length === 1) {
      if (!lobby.serverCreated) {
        lobby.serverCreated = true;
        const finalMap = remainingMaps[0];
        const { port, jobName } = await createOrUpdateCsServerJob(lobbyId, finalMap);
        lobby.jobName = jobName;
        lobby.serverCreatedAt = Date.now();
        io.to(lobbyId).emit('lobbyCreated', {
          serverIp: '192.168.2.69',
          serverPort: port,
          mapName: finalMap
        });
        lobby.turn = null;
        if (banTimers[lobbyId] && banTimers[lobbyId].timer) {
          clearTimeout(banTimers[lobbyId].timer);
        }
      }
      return;
    }
    lobby.turn = lobby.turn === 'team1' ? 'team2' : 'team1';
    io.to(lobbyId).emit('turnChanged', { currentTurn: lobby.turn });
    startCountdown(lobbyId, lobby.turn);
  });
  // Disconnection
  socket.on('disconnect', async () => {
    console.log(`Socket ${socket.id} disconnected.`);
    const lobbyId = socket.lobbyId;
    let db = null; // Declare db outside try block
    
    try {
      db = await mysql.createConnection(dbConfigMatchmaking);
      const [players] = await db.query('SELECT * FROM players WHERE socket_id = ?', [socket.id]);
      
      if (players.length > 0) {
        const player = players[0];
        await db.query('DELETE FROM queue WHERE player_id = ?', [player.id]);
        console.log(`Player ${player.name} removed from queue.`);

        // Remove player from in-memory lobby state
        if (lobbyId && lobbies[lobbyId]) {
          const lobby = lobbies[lobbyId];
          lobby.players = lobby.players.filter(p => p.socket_id !== socket.id);
          
          // Clean up lobby if empty
          if (lobby.players.length === 0) {
            // Stop any active ban timer
            if (banTimers[lobbyId]) {
              clearTimeout(banTimers[lobbyId].timer);
              delete banTimers[lobbyId];
            }
            
            // ONLY delete job if server was NEVER created
            if (!lobby.serverCreated && lobby.jobName) {
              try {
                await k8sBatchApi.deleteNamespacedJob(lobby.jobName, 'default');
                console.log(`Deleted abandoned job: ${lobby.jobName}`);
              } catch (error) {
                console.error('Error deleting pre-server job:', error.body || error);
              }
            }
            
            delete lobbies[lobbyId];
            console.log(`Lobby ${lobbyId} cleaned up ${lobby.serverCreated ? '(server remains active)' : ''}`);
          }
        }
      }
    } catch (error) {
      console.error('Error on disconnect:', error);
    } finally {
      if (db) { // Only end connection if it was established
        await db.end();
      }
    }
  });
});
  
// Start server
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
