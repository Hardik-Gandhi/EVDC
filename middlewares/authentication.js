const passport = require('passport');
const { capitalizeFirstLetter } = require('../utils/helper');

const handleJWT = (req, res, next) => async (err, user, info) => {
  if (err || info || !user) {
    let error = err || info.message == "jwt expired" ? "Invalid token" : info.messag;
    return res
      .status(401)
      .sendJson(error ? capitalizeFirstLetter(error) : 'Unauthorized access');
  }
  req.user = user;
  return next();
};

exports.isAuthenticated = (req, res, next) => {
  passport.authenticate(
    'jwt',
    { session: false },
    handleJWT(req, res, next)
  )(req, res, next);
};

exports.validateRole = (roles) => (req, res, next) => {
  roles = typeof roles == 'string' ? [roles] : roles || [];
  let userRoles = req.user ? [req.user.role] : [];
  if (! userRoles.some((role) => roles.includes(role))) {
    return res.status(403).sendJson("You don't have sufficient access permission!");
  }
  return next()
};