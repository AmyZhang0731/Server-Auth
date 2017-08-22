const User = require('../models/user');
const jwt = require('jwt-simple');
const config = require('../config');

function tokenForUser(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret); // subject of the token is user.id, issue at time
}

exports.signin = function(req, res, next) {
  // User has already had their auth, just nned to assign token
  res.send({ token: tokenForUser(req.user) });
}

exports.signup = function(req, res, next) {
  // console.log(req.body); body is require data
  const email = req.body.email;
  const password = req.body.password;

  if(!email || !password) { // validation
    return res.status(422).send({ error: 'You must provide an email and password'}); // unproccessable
  }


  // See if a user with a given e-mail exists
  User.findOne({ email: email }, function(err, existingUser) {
    if (err) { return next(err); }

    // If a user does exist, return error
    if(existingUser) {
      return res.status(422).send({ error: 'Email is in use'}); // unproccessable
    }

    // If not, create and save user record
    const user = new User({
      email: email,
      password: password
    });

    user.save(function(err) {
      if (err) { return next(err); }
    });

    // Respond to request indicating the user was created
    res.json({ token: tokenForUser(user) });

  }); // ,callback


}
