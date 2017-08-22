const passport = require("passport");
const User = require('../models/user');
const config = require('../config');
const JwtStrategy = require('passport-jwt').Strategy;
const LocalStrategy = require('passport-local');
const ExtractJwt = require('passport-jwt').ExtractJwt;

// Create local strategy
const localOptions = { usernameField: 'email' };
const localLogin = new LocalStrategy(localOptions, function(email, password, done) {
  // Verify pwd call done with user id it is correct else call done with false
  User.findOne({ email: email }, function(err, user) {
    if (err) { return done(err); }  // no user in search
    if (!user) { return done(null, false); }

    //compare pwd - is 'pwd' equal to user.password?
    user.comparePassword(password, function(err, isMatch) {
      if (err) { return done(err); }
      if (!isMatch) { return done(null, false); }

      return done(null, user);
    });
  });
});

// Setup options for JWT strategy
const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader('authorization'),
  secretOrKey: config.secret
};

// Create a JWT strategy
const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) { // payload: decoded jwt token, sub, iat, etc.
  // see if the user id exist
  // if does call done with that user
  // else call done without user object
  User.findById(payload.sub, function(err, user) {
    if (err) { return done(err, false); }  // no user in search

    if (user) {
      done(null, user); // find user
    } else {
      done(null, false); // can't find though no err when search
    }
  });

});

// Tell passport to use this strategy
passport.use(jwtLogin);
passport.use(localLogin);
