# U2F in Node.js

## Example Code
A working example of the topics in this tutorial can be found at [this link](https://tonsmann.me)
and all of the corresponding code this github repository:


## Requirements
In this project we use the following:
* Node.js
* Express
* MongoDB
* Mongoose
* Passport

We assume that you already have a website with a SSL certificate. We will explain how to
properly authenticate users using the Passport framework for local authentication, as well
as add U2F using the FIDO U2F protocol.

## User authentication
### User Model
We will be storing our user information in a MongoDB database, and using Mongoose as middleware
to access our MongoDB instance from Express. Here is how we model our User schema in
our Users.js model:

````javascript
const mongoose = require('mongoose');
const crypto = require('crypto');

const Schema = mongoose.Schema;

/**
 * User schema
 */

const deviceRegistrationSchema = new Schema({
  keyHandle: {type: String, default: ''},
  publicKey: {type: String, default: ''},
  certificate: {type: String, default: ''}
});

const UserSchema = new Schema({
  name: { type: String, default: '' },
  email: { type: String, default: '' },
  username: { type: String, default: '' },
  hashed_password: { type: String, default: '' },
  salt: { type: String, default: '' },
  deviceRegistration: {
    type: deviceRegistrationSchema,
    required: false
  }
});
````

Most values are stored as simple Strings here, but storing the info we will need later to
enable U2F is a little bit trickier. We first declare a ````deviceRegistrationSchema````
schema with the properties need to work with the U2F API, then use this new schema within
the ````UserSchema```` schema.

The values we care about now are the ````name````, ````email````, ````username````,
````hashed_password```` and ````salt```` fields. These are the values that we fill upon
the first step of registration. Lets talk about how to complete the User Model before getting
into form submission.

Mongoose requires that we have validations for certain values, to ensure that only valid values
are inserted into the database. Our validations simply check that no fields are blank, and that
the user cannot create multiple accounts for one email.

````javascript
const validatePresenceOf = value => value && value.length;

UserSchema.path('name').validate(function (name) {
  return name.length;
}, 'Name cannot be blank');

UserSchema.path('email').validate(function (email) {
  return email.length;
}, 'Email cannot be blank');

UserSchema.path('email').validate(function (email, fn) {
  const User = mongoose.model('User');

  // Check only when it is a new user or when email field is modified
  if (this.isNew || this.isModified('email')) {
    User.find({ email: email }).exec(function (err, users) {
      fn(!err && users.length === 0);
    });
  } else fn(true);
}, 'Email already exists');

UserSchema.path('username').validate(function (username) {
  return username.length;
}, 'Username cannot be blank');

UserSchema.path('hashed_password').validate(function (hashed_password) {
  return hashed_password.length && this._password.length;
}, 'Password cannot be blank');
````

Mongoose requires all models to have a pre-save hook:

````javascript
UserSchema.pre('save', function (next) {
  if (!this.isNew) return next();

  if (!validatePresenceOf(this.password)) {
    next(new Error('Invalid password'));
  } else {
    next();
  }
});
````

This will be called on every update of the model.

Now hopefully were not surprised when noticing that there is no ````password```` field in our
User model. We are following best practices by only storing the Salt and Hash of each user's
password. To authenticate a user, we simply hash their password and combine it with the salt
stored for their username, and if it matches their stored ````hashed_password```` then they
are authenticated.

It is important to note that it is critical that the whole site be encrypted using SSL/TLS.
If the site is not using SSL/TLS, then the plaintext password would be sent unencrypted over
the network before it reaches our webserver. This could be trivially intercepted by a
Man-in-the-Middle attack if the site does not properly implement SSL/TLS.

We use a virtual function to fill in the ````salt```` and ````hashed_password```` fields from
the user supplied password:
````javascript
UserSchema
  .virtual('password')
  .set(function (password) {
    this._password = password;
    this.salt = this.makeSalt();
    this.hashed_password = this.encryptPassword(password);
  })
  .get(function () {
    return this._password;
});
````
The methods mentioned in this virtual function are actually quite simple, and we define them
below:
````javascript
UserSchema.methods = {

  authenticate: function (plainText) {
    return this.encryptPassword(plainText) === this.hashed_password;
  },

  makeSalt: function () {
    return crypto.randomBytes(128).toString('base64');
  },

  encryptPassword: function (password) {
    if (!password) return '';
    try {
      const key = crypto.pbkdf2Sync(password, this.salt, 100000, 512, 'sha512');
      return key.toString('hex');
    } catch (err) {
      return '';
    }
  },
};
````

We set the ````salt```` for each user as a different cryptographically random string of 128
bytes. The ````hashed_password```` is calculated using the PBKDF2 algorithm with the
plaintext password and the salt as inputs, as well as parameters for the number of iterations
and size. We use PBKDF2 because it is a slow hashing algorithm, unlike SHA512 which is designed
for speed. When it comes to hashing passwords, we want a slow hashing algorithm to prevent
brute force attacks as well as to prevent cracking passwords if an attacker gets ahold of our
user database.

TODO: explain relevant methods in controllers/users.js and routing
