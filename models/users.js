const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const Schema = mongoose.Schema;
const ObjectId = Schema.ObjectId;

/*
** Collection Name: Users
*/

const UserSchema = new Schema(
  {
    firstName       : { type : String, default : null },
    lastName        : { type : String, default : null },
    email           : { type: String, default : null, trim: true, unique : true },
    googleId        : { type : String, default : null },
    facebookId      : { type :  String, default : null },
    password        : { type: String, default : null },
    mobile          : { type: String, default: null },
    isDeleted       : { type: Boolean, default: false },
    deletedBy       : { type: ObjectId, ref: 'user', default: null },
    deletedAt       : { type: Date, default: null },
  },
  { timestamps: true }
);

/*
**  Generate password hash
*/
UserSchema.pre('save', async function (next) {
  if (!this.isModified('password')) return next();
  const hash = await bcrypt.hash(this.password, 10);
  this.password = hash;
  next();
});

/*
**  Check unique email
*/
UserSchema.pre('save', true, function (next, done) {
  var self = this;
  mongoose.models['user'].findOne({
    _id: { $ne: self._id },
    email: self.email,
    isDeleted: false
  },
  function (err, user) {
    if (err || user) {
      done(err ? err : new Error('This email is already registered.'));
    }
    done();
  });
  next();
});

/*
**  Validate users password
*/
UserSchema.methods.isValidPassword = async function (password) {
  const user = this;
  const compare = await bcrypt.compare(password, user.password);
  return compare;
};

module.exports = mongoose.model('user', UserSchema, 'users');