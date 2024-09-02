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
const DEFAULT_PROFILE_PICTURE = 'https://path.to/default/profile-pic.jpg'; // Ensure you have a default image at this path

const dbConfig = {
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
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
    console.log('Steam profile:', profile);
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
        res.redirect('/profile'); // Redirect to profile after login
    }
);

app.get('/auth/guest', (req, res) => {
    const guestUser = {
        id: `guest_${Math.random().toString(36).substring(2, 15)}`,
        username: 'Guest',
        photos: [{ value: DEFAULT_PROFILE_PICTURE }] // Default profile picture for guests
    };
    req.session.passport = { user: guestUser };  // Simulate passport behavior for guest
    res.redirect('/profile'); // Redirect to profile for guests
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
    socket.on('startMatchmaking', async (user) => {
        user.socketId = socket.id;

        console.log('User object:', user);

        const db = await mysql.createConnection(dbConfig);
        try {
            console.log('Connecting to database...');
            console.log('Inserting player into players table...');

            const profilePicture = user.photos && user.photos.length > 0 ? user.photos[0].value : DEFAULT_PROFILE_PICTURE;

            const [insertResult] = await db.query('INSERT INTO players (socket_id, name, profile_picture) VALUES (?, ?, ?)', 
                [user.socketId, user.username, profilePicture]);
            console.log('Player inserted:', insertResult);

            const playerId = insertResult.insertId;

            console.log('Inserting player into queue...');
            await db.query('INSERT INTO queue (player_id) VALUES (?)', [playerId]);

            console.log('Fetching updated queue...');
            const [queue] = await db.query('SELECT * FROM queue');
            console.log('Queue fetched:', queue);

            if (!queue.length) {
                console.error('Queue is empty');
                return;
            }
            const matchmakingQueue = queue.map(q => ({ playerId: q.player_id }));
            console.log('Matchmaking queue:', matchmakingQueue);

            await checkQueueAndFormLobby(matchmakingQueue, db);
        } catch (error) {
            console.error('Error interacting with database:', error);
        } finally {
            await db.end();
        }
    });

    async function checkQueueAndFormLobby(matchmakingQueue, db) {
        if (matchmakingQueue.length >= 2) {
            const players = matchmakingQueue.splice(0, 2);
            const playerIds = players.map(player => player.playerId);

            console.log('Fetching player details for IDs:', playerIds);
            const [playerDetails] = await db.query('SELECT * FROM players WHERE id IN (?)', [playerIds]);
            console.log('Player details fetched:', playerDetails);

            if (playerDetails.length === 2) {
                console.log('Forming lobby for players:', playerDetails);

                const lobbyId = generateUniqueName('lobby');
                lobbies[lobbyId] = {
                    players: playerDetails,
                    mapSelected: false
                };

                // Update the lobby_id for matched players
                await db.query('UPDATE players SET lobby_id = ? WHERE id IN (?)', [lobbyId, playerIds]);
                playerDetails.forEach(player => player.lobby_id = lobbyId); // Update the lobby_id in player objects
                await db.query('DELETE FROM queue WHERE player_id IN (?)', [playerIds]);
                console.log('Removed matched players from queue:', playerIds);

                playerDetails.forEach((player) => {
                    io.to(player.socket_id).emit('lobbyReady', { lobbyId, players: playerDetails });
                    console.log(`Emitted lobbyReady to ${player.socket_id} with lobbyId ${lobbyId}`);
                    io.to(player.socket_id).emit('redirect', `/lobby.html?lobbyId=${lobbyId}`);
                });
            } else {
                console.log('Not enough players in queue to form a lobby');
            }
        } else {
            console.log('Not enough players in queue to form a lobby');
        }
    }

    socket.on('mapSelected', async (data) => {
        const lobbyId = data.lobbyId;
        if (!lobbies[lobbyId]) {
            console.error('Lobby does not exist:', lobbyId);
            return;
        }
        const { mapName } = data;
        lobbies[lobbyId].selectedMap = mapName;

        try {
            const { port, jobName } = await createOrUpdateCsServerJob(lobbyId, mapName);
            io.emit('lobbyCreated', {
                serverIp: '192.168.50.238',
                serverPort: port,
                mapName: mapName
            });
        } catch (error) {
            console.error('Error in server provisioning:', error);
        }
    });
});

server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
