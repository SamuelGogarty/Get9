require('dotenv').config();
const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const passport = require('passport');
const SteamStrategy = require('passport-steam').Strategy;
const session = require('express-session');
const { KubeConfig, BatchV1Api } = require('@kubernetes/client-node');
const fs = require('fs');
const yaml = require('js-yaml');
const crypto = require('crypto');
const mysql = require('mysql2/promise');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

const kc = new KubeConfig();
kc.loadFromDefault();
const k8sBatchApi = kc.makeApiClient(BatchV1Api);

const PORT = 3000;
const DEFAULT_PROFILE_PICTURE = 'https://path.to/default/profile-pic.jpg';

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
    saveUninitialized: false
}));

passport.use(new SteamStrategy({
    returnURL: 'http://192.168.50.238:3000/auth/steam/callback',
    realm: 'http://192.168.50.238:3000/',
    apiKey: process.env.STEAM_API_KEY
}, (identifier, profile, done) => {
    profile.username = profile.displayName || 'Unknown user';
    profile.photos = profile.photos || [{ value: DEFAULT_PROFILE_PICTURE }];
    profile.steamId = profile.id;
    return done(null, profile);
}));

passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser((user, done) => {
    done(null, user);
});

app.use(passport.initialize());
app.use(passport.session());

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

app.get('/auth/guest', (req, res) => {
    const guestUser = {
        id: `guest_${Math.random().toString(36).substring(2, 15)}`,
        username: 'Guest',
        photos: [{ value: DEFAULT_PROFILE_PICTURE }]
    };
    req.session.passport = { user: guestUser };
    res.redirect('/profile');
});

app.get('/profile', (req, res) => {
    if (req.isAuthenticated() || req.session.passport) {
        res.sendFile(path.join(__dirname, 'public', 'profile.html'));
    } else {
        res.redirect('/');
    }
});

app.get('/user/info', (req, res) => {
    if (req.isAuthenticated() || req.session.passport) {
        const user = req.user || req.session.passport.user;
        res.json({
            username: user.username,
            steamId: user.steamId,
            profilePictureUrl: user.photos && user.photos.length > 0 ? user.photos[0].value : DEFAULT_PROFILE_PICTURE
        });
    } else {
        res.status(401).send('User not authenticated');
    }
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

function generateUniqueName(baseName) {
    const randomString = crypto.randomBytes(4).toString('hex');
    return `${baseName}-${randomString}`.toLowerCase();
}

function getRandomPort() {
    const min = 27015;
    const max = 27030;
    return Math.floor(Math.random() * (max - min + 1)) + min;
}

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

let lobbies = {};

io.on('connection', (socket) => {
    // When players join a lobby, we store available maps
    socket.on('joinLobby', async ({ lobbyId }) => {
        if (!lobbies[lobbyId]) {
            lobbies[lobbyId] = {
                players: [],
                availableMaps: ['de_dust2', 'de_inferno'], // Add your maps here
                bannedMaps: []
            };
        }

        socket.join(lobbyId); // Add player to the lobby
    });

    socket.on('startMatchmaking', async (user) => {
        user.socketId = socket.id;

        const db = await mysql.createConnection(dbConfigMatchmaking);
        try {
            console.log('Inserting player into players table...');
            const profilePicture = user.photos && user.photos.length > 0 ? user.photos[0].value : DEFAULT_PROFILE_PICTURE;

            const [insertResult] = await db.query('INSERT INTO players (socket_id, name, profile_picture) VALUES (?, ?, ?)',
                [user.socketId, user.username, profilePicture]);

            const playerId = insertResult.insertId;

            await db.query('INSERT INTO queue (player_id) VALUES (?)', [playerId]);

            const [queue] = await db.query('SELECT * FROM queue');
            const matchmakingQueue = queue.map(q => ({ playerId: q.player_id }));

            await checkQueueAndFormLobby(matchmakingQueue, db);
        } catch (error) {
            console.error('Error interacting with matchmaking database:', error);
        } finally {
            await db.end();
        }
    });

    async function checkQueueAndFormLobby(matchmakingQueue, db) {
        if (matchmakingQueue.length >= 2) { // Adjust the number of players needed for a lobby
            const players = matchmakingQueue.splice(0, 2); // Pair two players
            const playerIds = players.map(player => player.playerId);

            const [playerDetails] = await db.query('SELECT * FROM players WHERE id IN (?)', [playerIds]);

            if (playerDetails.length === 2) {
                const lobbyId = generateUniqueName('lobby');
                lobbies[lobbyId] = {
                    players: playerDetails,
                    mapSelected: false,
                    availableMaps: ['de_dust2', 'de_inferno'], // Add available maps here
                    bannedMaps: []
                };

                await db.query('UPDATE players SET lobby_id = ? WHERE id IN (?)', [lobbyId, playerIds]);
                await db.query('DELETE FROM queue WHERE player_id IN (?)', [playerIds]);

                playerDetails.forEach((player) => {
                    io.to(player.socket_id).emit('lobbyReady', { lobbyId, players: playerDetails });
                    io.to(player.socket_id).emit('redirect', `/lobby.html?lobbyId=${lobbyId}`);
                });
            }
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

                // Pass the final map to Kubernetes and launch the server
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
        io.emit('publicChatMessage', data); // Broadcast to all players
    });

    socket.on('teamChatMessage', (data) => {
        // Broadcast the team message only to players in the same lobby
        const lobbyId = Object.keys(socket.rooms).find(room => room !== socket.id);
        io.to(lobbyId).emit('teamChatMessage', data);
    });
});

server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
