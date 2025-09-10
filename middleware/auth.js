// middleware/auth.js
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated && req.isAuthenticated()) return next();
  // for page routes you could redirect instead:
  // return res.redirect('/login');
  res.status(401).json({ error: 'Not authenticated' });
}

module.exports = { ensureAuthenticated };
