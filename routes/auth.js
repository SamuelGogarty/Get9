// middleware/auth.js
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  // For API routes we send JSON; for pages you can still redirect in server.js
  res.status(401).json({ error: 'Not authenticated' });
}
module.exports = { ensureAuthenticated };
