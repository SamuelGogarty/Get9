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

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

const kc = new KubeConfig();
kc.loadFromDefault();
const k8sBatchApi = kc.makeApiClient(BatchV1Api);

const PORT = 3000;
const DEFAULT_PROFILE_PICTURE = '/path/to/default/profile-pic.jpg'; // Ensure you have a default image at this path

app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'replace_with_a_strong_secret_key',
    resave: false,
    saveUninitialized: false
}));

passport.use(new SteamStrategy({
    returnURL: 'http://10.0.0.233:3000/auth/steam/callback',
    realm: 'http://10.0.0.233:3000/',
    apiKey: ''
}, (identifier, profile, done) => {
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
        res.redirect('/profile.html'); // Redirect to profile.html after login
    }
);

app.get('/auth/guest', (req, res) => {
    const guestUser = {
        id: `guest_${Math.random().toString(36).substring(2, 15)}`,
        displayName: 'Guest',
        photos: [{ value: DEFAULT_PROFILE_PICTURE }] // Default profile picture for guests
    };
    req.session.passport = { user: guestUser };  // Simulate passport behavior for guest
    res.redirect('/profile.html'); // Redirect to profile.html for guests
});

app.get('/lobby', (req, res) => {
    if (req.isAuthenticated() || req.session.user) {
        res.sendFile(path.join(__dirname, 'public', 'lobby.html'));
    } else {
        res.redirect('/');
    }
});

app.get('/user/info', (req, res) => {
    if (req.isAuthenticated() || req.session.user) {
        const user = req.user || req.session.user;
        res.json({
            id: user.id,
            displayName: user.displayName,
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
let matchmakingQueue = [];

io.on('connection', (socket) => {
    socket.on('startMatchmaking', (user) => {
        user.socketId = socket.id;
        matchmakingQueue.push(user);
        checkQueueAndFormLobby();
    });

    function checkQueueAndFormLobby() {
        if (matchmakingQueue.length >= 2) {
            const players = matchmakingQueue.splice(0, 10);
            formLobby(players);
        }
    }

    function formLobby(players) {
        const lobbyId = generateUniqueName('lobby');
        lobbies[lobbyId] = {
            players: players,
            mapSelected: false
        };
        players.forEach(player => {
            io.to(player.socketId).emit('lobbyReady', { lobbyId, players: lobbies[lobbyId].players });
            io.to(player.socketId).emit('redirect', `/lobby.html?lobbyId=${lobbyId}`);
        });
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
                serverIp: '10.0.0.233',
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
