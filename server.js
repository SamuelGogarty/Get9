const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const path = require('path');
const passport = require('passport');
const SteamStrategy = require('passport-steam').Strategy;
const session = require('express-session');
const mysql = require('mysql2/promise');

const app = express();
const server = http.createServer(app);
const io = socketIo(server);

const db = mysql.createPool({
    host: 'your-database-host',
    user: 'your-database-user',
    password: 'your-database-password',
    database: 'your-database-name'
});

passport.use(new SteamStrategy({
    returnURL: 'http://10.0.0.233:3000/auth/steam/callback',
    realm: 'http://10.0.0.233:3000/',
    apiKey: '<redacted>'
}, async (identifier, profile, done) => {
    // Optionally update or insert the user into your database here
    // For example, check if the user exists, if not, insert them
    const steamId = profile.id;

    try {
        const [rows] = await db.query('SELECT * FROM users WHERE steam_id = ?', [steamId]);
        if (rows.length === 0) {
            await db.query('INSERT INTO users (steam_id, elo) VALUES (?, ?)', [steamId, 1000]); // Default ELO rating
        }
        return done(null, profile);
    } catch (error) {
        return done(error);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const [rows] = await db.query('SELECT * FROM users WHERE steam_id = ?', [id]);
        done(null, rows[0]);
    } catch (error) {
        done(error, null);
    }
});

app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: 'replace_with_a_strong_secret_key',
    resave: false,
    saveUninitialized: false
}));
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

app.get('/lobby', (req, res) => {
    if (req.isAuthenticated()) {
        res.sendFile(path.join(__dirname, 'public', 'lobby.html'));
    } else {
        res.redirect('/');
    }
});

app.get('/user/info', async (req, res) => {
    if (req.isAuthenticated()) {
        const steamId = req.user.steam_id; // Assuming you have a steam_id column in your users table
        const [rows] = await db.query('SELECT * FROM users WHERE steam_id = ?', [steamId]);
        if (rows.length > 0) {
            const user = rows[0];
            res.json({ 
                id: user.steam_id, 
                displayName: req.user.displayName, 
                profilePictureUrl: req.user.photos[0].value,
                elo: user.elo 
            });
        } else {
            res.status(404).send('User not found');
        }
    } else {
        res.status(401).send('User not authenticated');
    }
});

// Add your socket.io and game server logic here...

server.listen(3000, () => {
    console.log('Server listening on port 3000');
});
