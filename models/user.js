const mongoose = require('mongoose');
const Schema = mongoose.Schema;
const bcrypt = require('bcrypt-nodejs');

// Define model
const userSchema = new Schema ({
  email: { type: String, unique: true, lowercase: true },
  password: String
})

// On Save Hook, encrypt password
userSchema.pre('save', function(next) { // pre save function
  // get access to the user model
  const user = this; // isntance

  // generate a salt then run callback
  bcrypt.genSalt(10, function(err, salt) {
    if (err) { return next(err); }

    // hash or encrypt our pwd using the salt
    bcrypt.hash(user.password, salt, null, function(err, hash) {
      if (err) { return nex(err); }

      // overwrite plain text pwd with encrypted one
      user.password = hash;
      next();
    });
  });
});

userSchema.methods.comparePassword = function(candidatePassword, callback) {
  bcrypt.compare(candidatePassword, this.password, function(err, isMatch) {
    if (err) { return callback(err); }

    callback(null, isMatch);
  });
}
// Create model class
const ModelClass = mongoose.model('user', userSchema);


// Export model
module.exports = ModelClass;
