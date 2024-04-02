const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const passport = require('passport');
const SteamStrategy = require('passport-steam').Strategy;
const session = require('express-session');
const { KubeConfig, AppsV1Api } = require('@kubernetes/client-node');
const fs = require('fs');
const yaml = require('js-yaml');
const crypto = require('crypto');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

const kc = new KubeConfig();
kc.loadFromDefault();
const k8sAppsApi = kc.makeApiClient(AppsV1Api);

const PORT = 3000;

app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'replace_with_a_strong_secret_key',
    resave: false,
    saveUninitialized: false
}));

passport.use(new SteamStrategy({
    returnURL: 'http://10.0.0.233:3000/auth/steam/callback',
    realm: 'http://10.0.0.233:3000/',
    apiKey: '<redacted>'
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
        res.redirect('/lobby');
    }
);

app.get('/auth/guest', (req, res) => {
    const guestUser = { id: `guest_${Math.random().toString(36).substring(2, 15)}`, displayName: 'Guest' };
    req.session.user = guestUser;
    res.redirect('/lobby');
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
        res.json({ id: user.id, displayName: user.displayName, profilePictureUrl: user.photos[0].value });
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

async function createOrUpdateCsServerPodAndService(lobbyId, mapName) {
    const port = getRandomPort();
    const deploymentName = generateUniqueName(`cs-server-${lobbyId}`);
    const templatePath = path.join(__dirname, 'k3s-manifest.yaml');

    let manifestTemplate = fs.readFileSync(templatePath, 'utf8');
    manifestTemplate = manifestTemplate.replace(/{{deploymentName}}/g, deploymentName)
                                       .replace(/{{port}}/g, port.toString())
                                       .replace(/{{mapName}}/g, mapName);

    const manifest = yaml.load(manifestTemplate);

    try {
        await k8sAppsApi.createNamespacedDeployment('default', manifest);
        console.log(`Deployment created: ${deploymentName} on port ${port}`);
        return { port, deploymentName };
    } catch (error) {
        console.error('Error creating deployment:', error);
        throw error;
    }
}

let lobbies = {};

io.on('connection', (socket) => {
    socket.on('joinLobby', (user) => {
        const lobbyId = 'defaultLobby';
        if (!lobbies[lobbyId]) {
            lobbies[lobbyId] = { team1: [], team2: [], selectedMap: '' };
        }
        lobbies[lobbyId].team1.push(user); // Or team2 based on logic
        io.emit('updateLobby', lobbies[lobbyId]);
    });

    socket.on('mapSelected', async (data) => {
        const lobbyId = 'defaultLobby';
        const { mapName } = data;
        lobbies[lobbyId].selectedMap = mapName;

        try {
            const { port, deploymentName } = await createOrUpdateCsServerPodAndService(lobbyId, mapName);
            io.emit('lobbyCreated', {
                serverIp: '10.0.0.233', // Replace with actual server IP
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
