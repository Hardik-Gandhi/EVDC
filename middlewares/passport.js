const passport = require('passport');
const localStrategy = require('passport-local').Strategy;
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const Joi = require('joi');

const config = require('../config');
const { removeFields, jsonToObject } = require('../utils/helper');

const USER = require('../models/users');

var opts = {};
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = config.jwtSecretKey;

// Passport serialize
passport.serializeUser(function(user, done) {
  done(null, user);
});


// Passport deserialize
passport.deserializeUser(function(user, done) {
  USER.findById(user._id, function(err, user) {
    done(err, user);
  });
});

// Create a passport middleware to handle user registration
passport.use(
  'signup',
  new localStrategy(
    {
      usernameField: 'email',
      passwordField: 'password',
      passReqToCallback: true,
    },
    async (req, email, password, done) => {
      try {
        const validationSchema = Joi.object({
          email: Joi.string().email().required(),
          password: Joi.string().required()
        });

        var validation = validationSchema.validate(req.body);
        if (validation.error) {
          return done({ joi: validation.error.details[0].message });
        }

        const payload = validation.value;
        const user = await USER(payload);
        user.save((err, user) => {
          if (err) done(err);
          else {
            user = removeFields(jsonToObject(user), ['password', 'createdBy', 'updatedBy'])
            return done(null, user);
          }
        });
      } catch (error) {
        return done(error);
      }
    }
  )
);


// Create a passport middleware to handle User login
passport.use(
  'login',
  new localStrategy(
    {
      usernameField: 'email',
      passwordField: 'password',
    },
    async (email, password, done) => {
      try {
        let user = await USER.findOne({ email, isDeleted: false});
        if (!user) {
          return done(null, false, {
            message: 'Invalid user email address',
          });
        }
        const validate = await user.isValidPassword(password);

        if (!validate) {
          return done(null, false, { message: 'Invalid password' });
        }
        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  )
);

// Passport Google auth strategy
passport.use(new GoogleStrategy({
  clientID: config.GOOGLE_CLIENTID,
  clientSecret: config.GOOGLE_SECRETKEY,
  callbackURL: config.GOOGLE_CALLBACK,
  accessType: 'offline',
  userProfileURL: 'https://www.googleapis.com/oauth2/v3/userinfo',
},
async function(accessToken, refreshToken, profile, cb) {
  var user = await USER.findOne({ googleId: profile.id, isDeleted: false });
  if(user) {
    return cb(null, user)
  } else {
    var newUser = new USER;
    newUser.googleId = profile.id
    newUser.email = profile.emails[0].value;
    newUser.firstName = profile.name.givenName;
    newUser.lastName = profile.name.familyName;
    newUser.save((err,data) => {
      if(err)
        return cb(err, null)
      return cb (null, data)
    });
  }
}));


passport.use(new FacebookStrategy({
  clientID: config.FACEBOOK_APPID,
  clientSecret: config.FACEBOOK_SECRET,
  callbackURL: config.FACEBOOK_CALLBACK,
  profileFields: ['id', 'displayName', 'photos', 'email']
},
async function(accessToken, refreshToken, profile, cb) {
  var user = await USER.findOne({ facebookId: profile.id, isDeleted: false });
  if(user) {
    return cb(null, user)
  } else {
    var newUser = new USER;
    newUser.facebookId = profile.id;
    newUser.firstName = profile.displayName.split(" ")[0];
    newUser.lastName = profile.displayName.split(" ")[1];
    newUser.save((err,data) => {
      if(err)
        return cb(err, null)
      return cb (null, data)
    });
  }
}));

// Verifies the token sent by the user is valid
passport.use(
  new JwtStrategy(opts, async function (jwtPayload, done) {
    try {
      let user = await USER.findOne({ _id: jwtPayload.user._id, email: jwtPayload.user.email, isDeleted: false });
      if (!user) {
        done('Invalid token', false);
      } else if (user) {
        user = removeFields(jsonToObject(user), ['password'])
        return done(null, user);
      }
    } catch (error) {
      return done(error, false);
    }
  })
);