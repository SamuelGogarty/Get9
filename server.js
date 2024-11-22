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

// Initialize Kubernetes client
const kc = new KubeConfig();
kc.loadFromDefault();
const k8sBatchApi = kc.makeApiClient(BatchV1Api);

const PORT = 3000;
const DEFAULT_PROFILE_PICTURE = 'https://path.to/default/profile-pic.jpg';

// Database configurations
const dbConfigMatchmaking = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: 'cs_matchmaking' // The database for matchmaking purposes
};

const dbConfigStats = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: 'stats' // The database for ELO stats
};

app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    // Use secure cookies in production
    // cookie: { secure: true }
}));
app.use(bodyParser.urlencoded({ extended: false }));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Steam Authentication Strategy
passport.use(new SteamStrategy({
    returnURL: 'http://192.168.50.238:3000/auth/steam/callback',
    realm: 'http://192.168.50.238:3000/',
    apiKey: process.env.STEAM_API_KEY,
    passReqToCallback: true
}, async (req, identifier, profile, done) => {
    try {
        profile.username = profile.displayName || 'Unknown user';
        profile.photos = profile.photos || [{ value: DEFAULT_PROFILE_PICTURE }];
        profile.steamId = profile.id;

        // Save or update the Steam user in the database
        const db = await mysql.createConnection(dbConfigMatchmaking);
        const [rows] = await db.query('SELECT * FROM users WHERE steam_id = ?', [profile.steamId]);

        let user;

        if (rows.length === 0) {
            // Insert new user
            const [insertResult] = await db.query('INSERT INTO users (username, steam_id, profile_picture, role, status, password_hash) VALUES (?, ?, ?, ?, ?, ?)', [
                profile.username,
                profile.steamId,
                profile.photos[0].value,
                'user',
                'active',
                ''
            ]);

            const userId = insertResult.insertId;

            // Insert initial ELO into ultimate_stats
            const dbStats = await mysql.createConnection(dbConfigStats);
            await dbStats.query('INSERT INTO ultimate_stats (steamid, skill) VALUES (?, ?)', [profile.steamId, 1000]); // Assuming 1000 is the default ELO
            await dbStats.end();

            // Build the user object with id
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
            await db.query('UPDATE users SET username = ?, profile_picture = ? WHERE steam_id = ?', [
                profile.username,
                profile.photos[0].value,
                profile.steamId
            ]);

            // Build the user object from the database
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

// Local Authentication Strategy
passport.use('local', new LocalStrategy(
    {
        usernameField: 'email',
        passwordField: 'password'
    },
    async (email, password, done) => {
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

            // User authenticated
            return done(null, user);
        } catch (err) {
            return done(err);
        }
    }
));

// Serialize and Deserialize User
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

        // If the user logged in with Steam, add steamId and profile_picture
        if (obj.type === 'steam') {
            user.steamId = user.steam_id;
            user.profile_picture = user.profile_picture || DEFAULT_PROFILE_PICTURE;
        }

        done(null, user);
    } catch (err) {
        done(err);
    }
});

// Middleware to ensure user is authenticated
function ensureAuthenticated(req, res, next) {
    if (req.isAuthenticated()) {
        return next();
    }
    res.redirect('/login');
}

// Middleware to ensure user is admin
function ensureAdmin(req, res, next) {
    if (req.isAuthenticated() && req.user.role === 'admin') {
        return next();
    } else {
        res.redirect('/login');
    }
}

// Utility functions
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
    return crypto.randomBytes(4).toString('hex'); // Generates an 8-character hex string
}

// Function to create or update the CS server job
async function createOrUpdateCsServerJob(lobbyId, mapName) {
    const port = getRandomPort();
    const jobName = generateUniqueName(`cs-server-${lobbyId}`);
    const templatePath = path.join(__dirname, 'k3s-manifest.yaml');

    let manifestTemplate = fs.readFileSync(templatePath, 'utf8');
    manifestTemplate = manifestTemplate.replace(/{{jobName}}/g, jobName)
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

// Routes
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Steam Authentication Routes
app.get('/auth/steam', passport.authenticate('steam'));
app.get('/auth/steam/callback',
    passport.authenticate('steam', { failureRedirect: '/' }),
    (req, res) => {
        res.redirect('/profile');
    }
);

// Local Authentication Routes
app.post('/login', passport.authenticate('local', {
    successRedirect: '/profile',
    failureRedirect: '/login?error=1'
}));

app.post('/register', async (req, res) => {
    const { username, email, password } = req.body;

    // Input validation
    if (!username || !email || !password) {
        return res.status(400).send('Please fill all fields.');
    }

    const passwordHash = await bcrypt.hash(password, 10);

    try {
        const db = await mysql.createConnection(dbConfigMatchmaking);
        const [result] = await db.query('INSERT INTO users (username, email, password_hash, role, status) VALUES (?, ?, ?, ?, ?)', [
            username,
            email,
            passwordHash,
            'user',
            'active'
        ]);

        const userId = result.insertId;

        // Insert initial ELO into ultimate_stats
        const dbStats = await mysql.createConnection(dbConfigStats);
        await dbStats.query('INSERT INTO ultimate_stats (steamid, skill) VALUES (?, ?)', [email, 1000]); // Assuming 1000 is the default ELO
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
        username: user.username,
        steamId: user.steamId || null,
        email: user.email || null,
        profilePictureUrl: user.profile_picture || DEFAULT_PROFILE_PICTURE
    });
});

app.get('/user/skill', async (req, res) => {
    if (req.isAuthenticated() || req.session.passport) {
        const user = req.user || req.session.passport.user;
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
    } else {
        res.status(401).send('User not authenticated');
    }
});

// Lobby and Pre-Lobby data structures
let lobbies = {};
let preLobbies = {}; // Key: inviteCode, Value: pre-lobby data

// Socket.io event handlers
io.on('connection', (socket) => {
    // When players join a lobby
    socket.on('joinLobby', async ({ lobbyId }) => {
        socket.join(lobbyId); // Add player to the lobby

        if (!lobbies[lobbyId] || !lobbies[lobbyId].players || lobbies[lobbyId].players.length === 0) {
            // Fetch players from the database
            const db = await mysql.createConnection(dbConfigMatchmaking);
            try {
                const [playerDetails] = await db.query('SELECT * FROM players WHERE lobby_id = ?', [lobbyId]);
                lobbies[lobbyId] = lobbies[lobbyId] || {
                    availableMaps: ['de_dust2', 'de_inferno'], // Add your maps here
                    bannedMaps: []
                };
                lobbies[lobbyId].players = playerDetails;

                // Fetch team assignments
                const teams = { team1: [], team2: [] };
                playerDetails.forEach((player) => {
                    if (player.team === 'team1') {
                        teams.team1.push(player);
                    } else if (player.team === 'team2') {
                        teams.team2.push(player);
                    }
                });
                lobbies[lobbyId].teams = teams;
            } catch (error) {
                console.error('Error fetching players for lobby:', error);
            } finally {
                await db.end();
            }
        }

        const lobby = lobbies[lobbyId];

        if (lobby && lobby.players) {
            // Send the lobby data to the client
            socket.emit('lobbyReady', { lobbyId, players: lobby.players, teams: lobby.teams });
        } else {
            socket.emit('error', 'Lobby not found or no players');
        }
    });

    // Start Matchmaking Event
    socket.on('startMatchmaking', async (user) => {
        user.socketId = socket.id;

        const db = await mysql.createConnection(dbConfigMatchmaking);
        try {
            let rows;

            if (user.steamId) {
                // Fetch user status using steam_id
                [rows] = await db.query('SELECT id, status, role FROM users WHERE steam_id = ?', [user.steamId]);
            } else if (user.email) {
                // Fetch user status using email
                [rows] = await db.query('SELECT id, status, role FROM users WHERE email = ?', [user.email]);
            } else {
                socket.emit('error', 'No identifier provided.');
                return;
            }

            if (rows.length === 0 || rows[0].status !== 'active') {
                socket.emit('error', 'Your account is not active.');
                return;
            }

            console.log(`User ${user.username} (${user.email || user.steamId}) is attempting to start matchmaking.`);

            // Check if player already exists in 'players' table
            let existingPlayer;
            if (user.steamId) {
                [existingPlayer] = await db.query('SELECT id FROM players WHERE steam_id = ?', [user.steamId]);
            } else if (user.email) {
                [existingPlayer] = await db.query('SELECT id FROM players WHERE email = ?', [user.email]);
            }

            let playerId;
            if (existingPlayer.length > 0) {
                playerId = existingPlayer[0].id;
                // Update the existing player's socket_id
                await db.query('UPDATE players SET socket_id = ? WHERE id = ?', [user.socketId, playerId]);
            } else {
                // Insert new player into 'players' table
                const [insertResult] = await db.query(
                    'INSERT INTO players (socket_id, name, profile_picture, steam_id, email) VALUES (?, ?, ?, ?, ?)',
                    [user.socketId, user.username, user.profilePictureUrl || DEFAULT_PROFILE_PICTURE, user.steamId || null, user.email || null]
                );

                playerId = insertResult.insertId;
            }

            // Check if player is already in queue
            const [queueRows] = await db.query('SELECT * FROM queue WHERE player_id = ?', [playerId]);
            if (queueRows.length > 0) {
                socket.emit('error', 'You are already in the matchmaking queue.');
                return;
            }

            // Add player to the queue
            await db.query('INSERT INTO queue (player_id) VALUES (?)', [playerId]);

            // Proceed with matchmaking
            const [queue] = await db.query('SELECT * FROM queue');
            const matchmakingQueue = queue.map((q) => ({ playerId: q.player_id }));

            await checkQueueAndFormLobby(matchmakingQueue, db);
        } catch (error) {
            console.error('Error interacting with matchmaking database:', error);
            socket.emit('error', 'Server error during matchmaking.');
        } finally {
            await db.end();
        }
    });

    // Pre-Lobby Events
    socket.on('createPreLobby', (user) => {
        const inviteCode = generateInviteCode();
        const preLobby = {
            inviteCode: inviteCode,
            leader: user,
            players: [user],
        };
        preLobbies[inviteCode] = preLobby;

        // Associate the socket with this pre-lobby
        socket.join(`preLobby_${inviteCode}`);

        // Send the invite code back to the creator
        socket.emit('preLobbyCreated', { inviteCode });
    });

    socket.on('joinPreLobby', ({ inviteCode, user }) => {
        const preLobby = preLobbies[inviteCode];
        if (preLobby) {
            user.socketId = socket.id;
            preLobby.players.push(user);

            // Associate the socket with this pre-lobby
            socket.join(`preLobby_${inviteCode}`);

            // Notify all players in the pre-lobby about the new player
            io.to(`preLobby_${inviteCode}`).emit('preLobbyUpdated', { players: preLobby.players });
        } else {
            socket.emit('error', 'Invalid invite code.');
        }
    });

    socket.on('startPreLobbyMatchmaking', async ({ inviteCode }) => {
        const preLobby = preLobbies[inviteCode];
        if (preLobby) {
            const groupId = generateUniqueName('group');

            const db = await mysql.createConnection(dbConfigMatchmaking);
            try {
                const playerIds = [];
                for (const user of preLobby.players) {
                    const profilePicture = user.profilePictureUrl || DEFAULT_PROFILE_PICTURE;

                    // Check if player already exists
                    let existingPlayer;
                    if (user.steamId) {
                        [existingPlayer] = await db.query('SELECT id FROM players WHERE steam_id = ?', [user.steamId]);
                    } else if (user.email) {
                        [existingPlayer] = await db.query('SELECT id FROM players WHERE email = ?', [user.email]);
                    }

                    let playerId;
                    if (existingPlayer.length > 0) {
                        playerId = existingPlayer[0].id;
                        // Update existing player
                        await db.query('UPDATE players SET socket_id = ?, group_id = ? WHERE id = ?', [user.socketId, groupId, playerId]);
                    } else {
                        // Insert new player
                        const [insertResult] = await db.query(
                            'INSERT INTO players (socket_id, name, profile_picture, group_id, steam_id, email) VALUES (?, ?, ?, ?, ?, ?)',
                            [user.socketId, user.username, profilePicture, groupId, user.steamId || null, user.email || null]
                        );
                        playerId = insertResult.insertId;
                    }

                    playerIds.push(playerId);

                    // Add player to the queue
                    await db.query('INSERT INTO queue (player_id) VALUES (?)', [playerId]);
                }

                const [queue] = await db.query('SELECT * FROM queue');
                const matchmakingQueue = queue.map((q) => ({ playerId: q.player_id }));

                await checkQueueAndFormLobby(matchmakingQueue, db);
            } catch (error) {
                console.error('Error in startPreLobbyMatchmaking:', error);
            } finally {
                await db.end();
            }

            // Remove the pre-lobby
            delete preLobbies[inviteCode];
        } else {
            socket.emit('error', 'Pre-lobby not found.');
        }
    });

    // Matchmaking Logic
    async function checkQueueAndFormLobby(matchmakingQueue, db) {
        // Group players by groupId
        const groupedPlayers = {};
        for (const player of matchmakingQueue) {
            const [playerData] = await db.query('SELECT * FROM players WHERE id = ?', [player.playerId]);
            const groupId = playerData[0].group_id || `solo_${player.playerId}`;
            if (!groupedPlayers[groupId]) {
                groupedPlayers[groupId] = [];
            }
            groupedPlayers[groupId].push(playerData[0]);
        }

        // Flatten the groups into an array while keeping the groupings
        const groups = Object.values(groupedPlayers);

        // Now, attempt to form lobbies considering the groups
        const requiredPlayers = 2; // Adjust as needed

        let lobbyPlayers = [];
        while (groups.length > 0 && lobbyPlayers.length < requiredPlayers) {
            const group = groups.shift();
            if (lobbyPlayers.length + group.length <= requiredPlayers) {
                lobbyPlayers = lobbyPlayers.concat(group);
            } else {
                // Not enough room for this group, push it back to the queue
                groups.push(group);
                break;
            }
        }

        if (lobbyPlayers.length === requiredPlayers) {
            const lobbyId = generateUniqueName('lobby');
            const team1 = [];
            const team2 = [];

            // Assign players to teams
            lobbyPlayers.forEach((player) => {
                if (player.group_id) {
                    // Place all players with the same group_id on the same team
                    if (!team1.some(p => p.group_id === player.group_id)) {
                        team1.push(player);
                        player.team = 'team1';
                    } else {
                        team2.push(player);
                        player.team = 'team2';
                    }
                } else {
                    // Assign solo players to teams to balance numbers
                    if (team1.length <= team2.length) {
                        team1.push(player);
                        player.team = 'team1';
                    } else {
                        team2.push(player);
                        player.team = 'team2';
                    }
                }
            });

            lobbies[lobbyId] = {
                players: lobbyPlayers,
                teams: {
                    team1: team1,
                    team2: team2,
                },
                mapSelected: false,
                availableMaps: ['de_dust2', 'de_inferno'],
                bannedMaps: [],
            };

            const playerIds = lobbyPlayers.map(player => player.id);
            const socketIds = lobbyPlayers.map(player => player.socket_id);

            for (const player of team1) {
                await db.query('UPDATE players SET lobby_id = ?, team = ? WHERE id = ?', [lobbyId, 'team1', player.id]);
            }
            for (const player of team2) {
                await db.query('UPDATE players SET lobby_id = ?, team = ? WHERE id = ?', [lobbyId, 'team2', player.id]);
            }

            await db.query('DELETE FROM queue WHERE player_id IN (?)', [playerIds]);

            socketIds.forEach((socketId) => {
                // Redirect players to the lobby page
                io.to(socketId).emit('redirect', `/lobby.html?lobbyId=${lobbyId}`);
            });
        }
    }

    // Handle map selection and banning
    socket.on('mapSelected', async (data) => {
        const lobbyId = data.lobbyId;
        const { mapName } = data;

        const lobby = lobbies[lobbyId];

        if (lobby) {
            // Add the map to the banned list
            lobby.bannedMaps.push(mapName);
            io.to(lobbyId).emit('mapBanned', { mapName });

            // Check if only one map is left
            const remainingMaps = lobby.availableMaps.filter(map => !lobby.bannedMaps.includes(map));
            if (remainingMaps.length === 1) {
                const finalMap = remainingMaps[0];

                // Call the function to create or update the CS server job
                const { port } = await createOrUpdateCsServerJob(lobbyId, finalMap);

                // Notify clients that the server is ready
                io.to(lobbyId).emit('lobbyCreated', {
                    serverIp: '192.168.50.238',
                    serverPort: port,
                    mapName: finalMap
                });
            }
        }
    });

    // Chat events
    socket.on('publicChatMessage', (data) => {
        const lobbyId = Object.keys(socket.rooms).find(room => room !== socket.id);
        if (lobbyId) {
            io.to(lobbyId).emit('publicChatMessage', data); // Broadcast to all players in the lobby
        }
    });

    socket.on('teamChatMessage', (data) => {
        const lobbyId = Object.keys(socket.rooms).find(room => room !== socket.id);
        if (lobbyId && lobbies[lobbyId]) {
            const player = lobbies[lobbyId].players.find(p => p.socket_id === socket.id);
            if (player) {
                const team = player.team;
                const teamSockets = lobbies[lobbyId].teams[team].map(player => player.socket_id);
                teamSockets.forEach(socketId => {
                    io.to(socketId).emit('teamChatMessage', data);
                });
            }
        }
    });

    // Handle player disconnection
    socket.on('disconnect', async () => {
        console.log(`Socket ${socket.id} disconnected.`);

        const db = await mysql.createConnection(dbConfigMatchmaking);
        try {
            // Find the player associated with this socket
            const [players] = await db.query('SELECT * FROM players WHERE socket_id = ?', [socket.id]);

            if (players.length > 0) {
                const player = players[0];

                // Remove the player from the queue
                await db.query('DELETE FROM queue WHERE player_id = ?', [player.id]);

                // Optionally, remove the player from the players table
                // await db.query('DELETE FROM players WHERE id = ?', [player.id]);

                console.log(`Player ${player.name} removed from queue.`);
            }
        } catch (error) {
            console.error('Error during disconnect handling:', error);
        } finally {
            await db.end();
        }
    });
});

// Admin Routes
app.get('/admin', ensureAdmin, (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// API route to get all users
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

// API route to update user status and role
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

// Start the server
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
