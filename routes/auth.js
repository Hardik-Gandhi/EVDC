const express = require('express');
const router = express.Router();
const passport = require('passport');
require('../middlewares/passport');
const { removeFields, jsonToObject, genrateJwt } = require('../utils/helper.js');
const { isAuthenticated } = require('../middlewares/authentication');
const Joi = require('joi');
const USER = require('../models/users');

// Root path
router.get('/', function (req, res, next) {
    res.redirect('/api-docs');
});

// SignUp
router.post('/signUp',async (req, res, next) => {
  passport.authenticate('signup', { session: false }, async (err, user, info) => {
    if (err || info) {
      if(err) {
        let statusCode = err.joi ? 422 : 201;
        err = err.joi ? err.joi : err.message;
        if(!res.headersSent) return res.status(statusCode).sendJson(err);
      } else {
        if(!res.headersSent) return res.status(201).sendJson(info && info.message ? info.message : 'Something went wrong while creating new User.');
      }
    } else {
      const body = { _id: user._id, email: user.email };
      const token = await genrateJwt(body);
      let responsePayload = removeFields(jsonToObject(user), ['password']);
      responsePayload['token'] = token;
      return res.status(200).sendJson({
        message: 'Signup successful',
        data: responsePayload,
      });
    }
  })(req, res, next)
});

// SignIn
router.post('/signIn', async (req, res, next) => {
    passport.authenticate('login', async (err, user, info) => {
      if (info && info.message) {
        return res.status(201).sendJson(info.message);
      }
  
      try {
        if (err || !user) {
          return res.status(401).sendJson("Unauthoried access");
        }
        req.login(user, { session: false }, async (error) => {
          if (error) return next(error);
          const body = { _id: user._id, email: user.email };
          const token = await genrateJwt(body);
          var responsePayload = removeFields(jsonToObject(user), ['password']);
          responsePayload['token'] = token;
          return res.sendJson(responsePayload);
        });
      } catch (error) {
        return res
          .status(201)
          .sendJson(error ? error.message : 'Error while login');
      }
    })(req, res, next);
});

// Google auth route
router.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

// Google auth callback route
router.get('/auth/google/callback',  passport.authenticate('google', { failureRedirect: '/googleFails' }), function(req, res) {

  // Handle Google auth success
  req.login(req.user, { session : false }, async (error) => {
    if( error )
      return  res.status(201).sendJson(error ? error.message : 'Error while google login');;

    const body = { _id : req.user._id, email : req.user.email, googleId: req.user.googleId };
    const token = await genrateJwt(body);
    var responsePayload = removeFields(jsonToObject(req.user), ['password']);
    responsePayload['token'] = token;
    return res.sendJson(responsePayload);
  })
});

// Handle Google auth failure
router.get('/googleFails', (req,res) => res.status(201).sendJson('Google Authentication Fails'));

//  Facebook auth route
router.get('/auth/facebook', passport.authenticate('facebook', {scope: 'email'}));

//  Facebook callback route
router.get('/auth/facebook/callback', passport.authenticate('facebook', { failureRedirect: '/facebookFails' }), (req, res) => {
  req.login(req.user, { session : false }, async (error) => {
    if( error )
      return error;

    const body = { _id : req.user._id, facebookId: req.user.facebookId };
    const token = await genrateJwt(body);
    var responsePayload = removeFields(jsonToObject(req.user), ['password']);
    responsePayload['token'] = token;
    return res.sendJson(responsePayload);
  });
});

// Handle Facebook auth failure
router.get('/facebookFails', (req,res) => res.status(201).sendJson('Facebook Authentication Fails'));

// Handle Facebook auth success
router.get('/facebookSuccess', async (req,res) => {
  req.login(req.user, { session : false }, async (error) => {
    if( error ) 
      return error;

    const body = { _id : req.user._id, facebookId: req.user.facebookId };
    const token = await genrateJwt(body);
    var responsePayload = removeFields(jsonToObject(req.user), ['password']);
    responsePayload['token'] = token;
    return res.sendJson(responsePayload);
  })
});

// Profile route
router.get('/profile', isAuthenticated, (req, res, next) => {
  if (req.user) {
    var responsePayload = removeFields(jsonToObject(req.user), ['password']);
    return res.sendJson(responsePayload);
  } else {
    return res.status(201).sendJson('Error while fetching profile details.');
  }
});

// Update profile
router.put('/profile', isAuthenticated, (req, res, next) => {
  const validationSchema = Joi.object({
    firstName: Joi.string().required(),
    lastName: Joi.string().required(),
    email: Joi.string().email().allow("").allow(null).optional(),
    mobile: Joi.string().allow("").allow(null).optional()
  });

  var validation = validationSchema.validate(req.body);
  if (validation.error) {
    return res.status(422).sendJson(validation.error.message);
  }

  const payload = validation.value;
  payload.updatedBy = req.user._id;

  USER.findOneAndUpdate({ _id: req.user._id, isDeleted: false }, { $set: payload }, { new: true })
  .then(user => {
    if(!user) {
      return res.status(404).sendJson("User not found.");
    }
    return res.status(200).sendJson(removeFields(jsonToObject(user)));
  })
  .catch((err) => res.status(201).sendJson(err ? err.message : "Something went wrong while updating user's profile."));
});

module.exports = router;