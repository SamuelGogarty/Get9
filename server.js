const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const passport = require('passport');
const SteamStrategy = require('passport-steam').Strategy;
const session = require('express-session');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

const PORT = 3000;

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
    apiKey: 'CA2410DAE8327980C04B378DCBB5B87E'
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

app.get('/auth/steam/callback', passport.authenticate('steam', {
    successRedirect: '/profile',
    failureRedirect: '/'
}));

app.get('/profile', (req, res) => {
    if (req.isAuthenticated()) {
        res.sendFile(path.join(__dirname, 'public', 'profile.html'));
    } else {
        res.redirect('/');
    }
});

app.get('/user/info', (req, res) => {
    if (req.isAuthenticated()) {
        res.json({
            id: req.user.id,
            displayName: req.user.displayName
        });
    } else {
        res.status(401).send('Not authenticated');
    }
});

let playerQueue = [];

io.on('connection', (socket) => {
    console.log('A user connected');
    
    socket.on('startMatchmaking', (playerData) => {
        console.log(`${playerData.username} is looking for a match`);
        playerQueue.push({ socketId: socket.id, ...playerData });

        if (playerQueue.length >= 2) {
            const lobbyPlayers = playerQueue.splice(0, 2);
            lobbyPlayers.forEach(player => {
                io.to(player.socketId).emit('lobbyCreated', lobbyPlayers);
            });
        }
    });

    socket.on('disconnect', () => {
        console.log('A user disconnected');
        playerQueue = playerQueue.filter(player => player.socketId !== socket.id);
    });
});

server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
