const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const passport = require('passport');
const SteamStrategy = require('passport-steam').Strategy;
const session = require('express-session');
const { KubeConfig, AppsV1Api } = require('@kubernetes/client-node');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

const kc = new KubeConfig();
kc.loadFromDefault();
const k8sAppsApi = kc.makeApiClient(AppsV1Api);

const PORT = 3000;
let basePort = 27015; // Starting port for CS servers

app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'replace_with_a_strong_secret_key',
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

passport.use(new SteamStrategy({
    returnURL: 'http://10.0.0.233:3000/auth/steam/callback',
    realm: 'http://10.0.0.233:3000/',
    apiKey: 'redacted'
}, (identifier, profile, done) => {
    return done(null, profile);
}));

passport.serializeUser((user, done) => {
    done(null, user);
});

passport.deserializeUser((user, done) => {
    done(null, user);
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.get('/auth/steam', passport.authenticate('steam'));
app.get('/auth/steam/callback', passport.authenticate('steam', { successRedirect: '/profile', failureRedirect: '/' }));
app.get('/auth/guest', (req, res) => {
    const guestUser = { id: `guest_${Math.random().toString(36).substring(2, 15)}`, displayName: 'Guest' };
    req.session.user = guestUser;
    res.redirect('/profile');
});

app.get('/profile', (req, res) => {
    if (req.isAuthenticated() || req.session.user) {
        res.sendFile(path.join(__dirname, 'public', 'profile.html'));
    } else {
        res.redirect('/');
    }
});

app.get('/user/info', (req, res) => {
    const user = req.isAuthenticated() ? req.user : req.session.user;
    res.json({ id: user.id, displayName: user.displayName });
});

let playerQueue = [];

async function createCsServerPod(port) {
    const deploymentName = `cs-server-${Math.random().toString(36).substring(2, 7)}`;
    const namespace = 'default'; // Replace with your actual namespace

    const deployment = {
        apiVersion: 'apps/v1',
        kind: 'Deployment',
        metadata: {
            name: deploymentName,
            namespace: namespace
        },
        spec: {
            replicas: 1,
            selector: {
                matchLabels: {
                    app: deploymentName
                }
            },
            template: {
                metadata: {
                    labels: {
                        app: deploymentName
                    }
                },
                spec: {
                    hostNetwork: true,
                    containers: [{
                        name: 'cs-server-container',
                        image: 'goldsourceservers/cstrike:latest',
                        command: ["/bin/bash", "-c"],
                        args: [`printenv && ls -al && exec hlds_linux -game cstrike +port ${port} +maxplayers 10 +map de_dust2`],
                        ports: [{ containerPort: port }]
                    }]
                }
            }
        }
    };

    try {
        await k8sAppsApi.createNamespacedDeployment(namespace, deployment);
        console.log('Deployment created:', deploymentName);
        return { deploymentName, port };
    } catch (err) {
        console.error('Error creating CS 1.6 server deployment:', err);
        throw err;
    }
}

io.on('connection', (socket) => {
    socket.on('startMatchmaking', async (playerData) => {
        playerQueue.push({ socketId: socket.id, ...playerData });

        if (playerQueue.length >= 2) {
            const lobbyPlayers = playerQueue.splice(0, 2);
            const port = basePort++;
            try {
                const { deploymentName, port: serverPort } = await createCsServerPod(port);
                console.log(`Server ${deploymentName} started on port ${serverPort}`);
                lobbyPlayers.forEach(player => {
                    io.to(player.socketId).emit('lobbyCreated', {
                        players: lobbyPlayers,
                        serverIp: '10.0.0.233', // Replace with actual server IP
                        serverPort: serverPort
                    });
                });
            } catch (error) {
                console.error('Error in matchmaking process:', error);
            }
        }
    });
});

server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
