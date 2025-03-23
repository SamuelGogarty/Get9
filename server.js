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

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

// Kubernetes client
const kc = new KubeConfig();
kc.loadFromDefault();
const k8sBatchApi = kc.makeApiClient(BatchV1Api);

const PORT = 3000;
const DEFAULT_PROFILE_PICTURE = '/img/nonsteam-profile.png';

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
  (req, res) => {
    res.redirect('/profile');
  }
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
    await db.query(
      'INSERT INTO users (username, email, password_hash, role, status) VALUES (?, ?, ?, ?, ?)',
      [username, email, passwordHash, 'user', 'active']
    );
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

// ----------------------------------------------------------
// Socket.io
// ----------------------------------------------------------
io.on('connection', (socket) => {
  // joinLobby
  socket.on('joinLobby', async ({ lobbyId, userId }) => {
    socket.join(lobbyId);
    socket.lobbyId = lobbyId;

    if (!lobbies[lobbyId]) {
      lobbies[lobbyId] = {
        availableMaps: ['de_dust2', 'de_inferno'],
        bannedMaps: [],
        players: [],
        teams: { team1: [], team2: [] }
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
      socket.emit('lobbyReady', {
        lobbyId,
        players: lobby.players,
        teams: lobby.teams
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

      // Add them to the queue
      await db.query('INSERT INTO queue (player_id) VALUES (?)', [playerId]);

      // Evaluate matchmaking
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
      const groupId = playerData[0].group_id || `solo_${playerData[0].id}`;
      if (!groupedPlayers[groupId]) groupedPlayers[groupId] = [];
      groupedPlayers[groupId].push(playerData[0]);
    }

    // For testing: require exactly 2 players
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

      // Force the first occupant on Team 1, second occupant on Team 2
      team1.push(lobbyPlayers[0]);
      lobbyPlayers[0].team = 'team1';

      team2.push(lobbyPlayers[1]);
      lobbyPlayers[1].team = 'team2';

      lobbies[lobbyId] = {
        players: lobbyPlayers,
        teams: { team1, team2 },
        availableMaps: ['de_dust2', 'de_inferno'],
        bannedMaps: []
      };

      const playerIds = lobbyPlayers.map(p => p.id);

      // Update DB with the assigned team
      await db.query('UPDATE players SET lobby_id = ?, team = ? WHERE id = ?', [lobbyId, 'team1', lobbyPlayers[0].id]);
      await db.query('UPDATE players SET lobby_id = ?, team = ? WHERE id = ?', [lobbyId, 'team2', lobbyPlayers[1].id]);

      // Remove them from the queue
      await db.query('DELETE FROM queue WHERE player_id IN (?)', [playerIds]);

      // Redirect them to the new lobby
      const socketIds = lobbyPlayers.map(p => p.socket_id);
      socketIds.forEach(sid => {
        io.to(sid).emit('redirect', `/lobby.html?lobbyId=${lobbyId}`);
      });
    }
  }

  // Map selection
  socket.on('mapSelected', async ({ lobbyId, mapName }) => {
    const lobby = lobbies[lobbyId];
    if (!lobby) return;
    lobby.bannedMaps.push(mapName);
    io.to(lobbyId).emit('mapBanned', { mapName });

    const remainingMaps = lobby.availableMaps.filter(m => !lobby.bannedMaps.includes(m));
    if (remainingMaps.length === 1) {
      const finalMap = remainingMaps[0];
      const { port } = await createOrUpdateCsServerJob(lobbyId, finalMap);

      io.to(lobbyId).emit('lobbyCreated', {
        serverIp: '192.168.2.69',
        serverPort: port,
        mapName: finalMap
      });
    }
  });

  // Disconnection
  socket.on('disconnect', async () => {
    console.log(`Socket ${socket.id} disconnected.`);
    const db = await mysql.createConnection(dbConfigMatchmaking);
    try {
      const [players] = await db.query('SELECT * FROM players WHERE socket_id = ?', [socket.id]);
      if (players.length > 0) {
        const player = players[0];
        await db.query('DELETE FROM queue WHERE player_id = ?', [player.id]);
        console.log(`Player ${player.name} removed from queue.`);
      }
    } catch (error) {
      console.error('Error on disconnect:', error);
    } finally {
      await db.end();
    }
  });
});

// Start server
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
