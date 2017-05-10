# U2F in Node.js

## Example Code
A working example of the topics in this tutorial can be found at [this link](https://tonsmann.me)
and all of the corresponding code this github repository:
https://github.com/mtonsmann/FIDO-U2F-Express-Passport-Example


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

If you have not used Express and Passport before, [this project](https://github.com/madhums/node-express-mongoose/) provides an excellent
starting point also has a wiki available [here](https://github.com/madhums/node-express-mongoose/wiki). This tutorial will use a
similar layout to this project.

The purpose of this tutorial is not to teach you the fundamentals of user authentication, but
to teach you how to implement the best practices. There is a complex overview of the FIDO U2F
protocol available [here](https://fidoalliance.org/).

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

The values we care about now are the ````name````, ````email````, ````username````,````hashed_password```` and ````salt```` fields.
These are the values that we fill upon the first step of registration. Lets talk about how to
complete the User Model before getting into form submission.

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


### Routing and Controllers

There are a few changes that we need to make to our sites routing in order to ensure that
certain pages are only available when a user is authenticated, as well as set up our
registration and login flow. If you are new to Express, all of our routing is handled
by ````config/routes.js````. In our example project, we handle all of the actual methods
called by the routing in a separate ````controllers```` directory, which we will go over next.

The following code is the routing we need for now, we will add more routes to support U2F
later.

````javascript
/*
 * Module dependencies.
 */

const users = require('../app/controllers/users');
const home = require('../app/controllers/home');
const auth = require('./middlewares/authorization');


const fail = {
  failureRedirect: '/login'
};

/**
 * Expose routes
 */

 module.exports = function (app, passport) {
   const pauth = passport.authenticate.bind(passport);

   // user routes
   app.get('/login', users.login);
   app.get('/signup', users.signup);
   app.get('/logout', users.logout);
   app.post('/users', users.create);
   app.post('/users/session',
     pauth('local', {
       failureRedirect: '/login',
       failureFlash: 'Invalid email or password.'
     }), users.session);

   app.param('userId', users.load);

   app.get('/', home.index);

   // see source for error handling

 };
````
Using a separate Controllers file leads to a simple routing method. GET and POST requests are
directed to the proper Javascript methods. For example, when we receive a HTTP GET request
for ````'/login'```` we call the ````login```` method of our ````users```` controller.
Let's take a look at the methods that our routing
calls on, located within the ````app/controllers/users.js```` file.

````javascript
/**
 * Load
 */

exports.load = async(function* (req, res, next, _id) {
  const criteria = { _id };
  try {
    req.profile = yield User.load({ criteria });
    if (!req.profile) return next(new Error('User not found'));
  } catch (err) {
    return next(err);
  }
  next();
});

/**
 * Create user
 */

exports.create = async(function* (req, res) {
  const user = new User(req.body);
  user.provider = 'local';
  try {
    yield user.save();
    req.logIn(user, err => {
      if (err) req.flash('info', 'Sorry! We are not able to log you in!');
      // used to direct to /, we changed it
      return res.redirect('/setup2fa');
    });
  } catch (err) {
    const errors = Object.keys(err.errors)
      .map(field => err.errors[field].message);

    res.render('users/signup', {
      title: 'Sign up',
      errors,
      user
    });
  }
});

/**
 *  Show profile
 */

exports.show = function (req, res) {
  const user = req.profile;
  respond(res, 'users/show', {
    title: user.name,
    user: user
  });
};

exports.signin = function () {};

/**
 * Auth callback
 */

exports.authCallback = login;

/**
 * Show login form
 */

exports.login = function (req, res) {
  res.render('users/login', {
    title: 'Login'
  });
};

/**
 * Show sign up form
 */

exports.signup = function (req, res) {
  res.render('users/signup', {
    title: 'Sign up',
    user: new User()
  });
};

/**
 * Logout
 */

exports.logout = function (req, res) {
  req.logout();
  req.session.secondFactor = undefined;
  res.redirect('/login');
};

/**
 * Session
 */

exports.session = login;

/**
 * Login
 */

 function login (req, res) {
  res.redirect('/2faCheck');
}
````
Most of these methods just told the site to render certain views for the user, but a few of
them handle some more complex tasks like creating and loading users. We will add more complex
methods in order to handle U2F in future steps.

Note that the login function redirects us to the ````2faCheck```` page, which we don't have
have a route for yet. We will add those routes in the U2F section. We want our users to be
directed to this page after they login so that they can finish the login process by providing
their U2F device.

### Passport Configuration

We just need to write one small function to finish up our username+password part of the
authentication. This is the login logic that will call functions in our User model to
authenticate users. This is part of Passport, so we will locate it at ````/config/passport/local.js````:

````javascript
/**
 * Module dependencies.
 */

var mongoose = require('mongoose');
var LocalStrategy = require('passport-local').Strategy;
var User = mongoose.model('User');

/**
 * Expose
 */

module.exports = new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password'
  },
  function (email, password, done) {
    var options = {
      criteria: { email: email }
    };
    User.load(options, function (err, user) {
      if (err) return done(err);
      if (!user) {
        return done(null, false, { message: 'Unknown user' });
      }
      if (!user.authenticate(password)) {
        return done(null, false, { message: 'Invalid password' });
      }
      return done(null, user);
    });
  }
);
````

All this function does is say if a particular email and password combination is valid. Most
of the work is done by the ````load```` function within our User model.

### Views

Most of the methods we have in the ````app/controllers/users.js```` file use the ````res.render()```` function to direct users to pages. We will go over the login and signup
pages here.

Our project uses Jade as the rendering language, which is compiled to HTML. This was a result
of piggybacking off of https://github.com/madhums/node-express-mongoose/.

Our views both extend ````auth```` which is some simple boilerplate stuff for maintaining the
overall feel of the site. I will just go over the important parts here. ````app/views/users/signup.jade````:

````
extends auth

block auth
  form.form-horizontal.form-signin(action="/users", method="post", role="form")
    input(type='hidden', name='_csrf', value="#{csrf_token}")

    input#email.form-control(type='text', name="email", placeholder='Email', value=user.email)

    input#name.form-control(type='text', name="name", placeholder='Full name', value=user.name)

    input#username.form-control(type='text', name="username", placeholder='Username', value=user.username)

    input#password.form-control(type='password', name="password", placeholder='Password')

    br
    .text-center
      button.btn.btn-primary(type='submit') Sign up
      br
      br
      a.show-login(href="/login") Log in
````
Upon submit, all of these values are saved in the request (````req````) which we can access
to create a ````User```` with these values. This is why it is absolutely critical that the
site be configured with SSL properly. Without SSL, the values entered into these fields (on
both the signup page and the login page) can be captured with a Man-in-the-Middle attack.

Also note the ````_csrf```` form on the page. This is protection against Cross Site Request
Forgery (CSRF). We use the csurf package to prevent CSRF on our site, which simplifies the
process of having hidden nonces on forms that ensure the forms we are receiving are valid.

Our login page is even simpler. Note the use of the CSRF token as well as the location of
an error message to appear if, for example, the password is incorrect. ````app/views/users/login.jade````:
````
extends auth

block auth
  form.form-horizontal.form-signin(action="/users/session", method="post", role="form")
    input(type="hidden", name="_csrf", value="#{csrf_token}")

    p.col-sm-offset-2.error= message

    input#email.form-control(type="email", placeholder="Email", name="email")

    input#password.form-control(type="password", placeholder="Password", name="password")

    br
    button.btn.btn-primary.btn-block(type="submit") Log in
    br

    .text-center
      a.show-signup(href="/signup") Sign up
````
Now we are ready to add U2F to our site.


## U2F with yubikey

This section details how to add support for FIDO U2F to your Express site. We tested our
site with Yubico Yubikeys. We make use of the Google implementation of the official U2F
API. Note that Chrome is currently the only browser that supports FIDO U2F without a plugin
or extension.

### Routing and Controllers

We need to add the following lines to our ````config/routes.js```` file with the rest of our
get and post methods. Note that our example site file can be seen in it's entirety at https://github.com/mtonsmann/FIDO-U2F-Express-Passport-Example.

````javascript
app.get('/u2f-api.js', users.api);
app.get('/2faCheck', auth.requiresLogin, users.twofacheck);
app.get('/setup2FA', users.setup2fa);
app.get('/registerU2F', auth.requiresLogin, users.registerGet);
app.post('/registerU2F', auth.requiresLogin, users.registerPost);
app.get('/authenticateU2F', auth.requiresLogin, users.authenticateGet);
app.post('/authenticateU2F', auth.requiresLogin, users.authenticatePost);

app.get('/users/:userId', auth.requires2FA, users.show);
````
These additional lines handle the GET and POST requests we need in order to add U2F. We can
recognize the familiar calls to our user controller, but many of these new routes also
have the ````auth.requiresLogin```` flag as well. This is to ensure that we users can only
reach this page if they have already authenticated themselves. This is important because
we have to know which user is trying to provide their second factor.

The ````app.get('/users/:userId', auth.requires2FA, users.show);```` line is the secret
page that only authenticated users are able to see. It uses the ````auth.requires2FA```` flag,
which is only true when the user has already authenticated themselves with their password as
well as U2F.

This properties are set up in the ````config/middlewares/authorization.js```` file:

````javascript
exports.requiresLogin = function (req, res, next) {
  if (req.isAuthenticated()) return next();
  if (req.method == 'GET') req.session.returnTo = req.originalUrl;
  res.redirect('/login');
};

exports.requires2FA = function (req, res, next) {
  if (req.isAuthenticated() && req.session.secondFactor) return next();
  if (req.method == 'GET') req.session.returnTo = req.originalUrl;
  res.redirect('/login');
};
````

It is worth noting that this simple set up does not differentiate between users. A more complex ````authorization.js```` is required for this to work.

Now let's look at the new methods our user controller needs in order to serve these GET and
POST requests. Once again these methods are all located in the ````app/controllers/users.js````
file, and our example file can be viewed in it's entirety at the Github page.

Firstly, we use the ````users.api```` function to give the user's browser access to Google's
Javascript API which we leverage to handle registering and authenticating U2F tokens:

````javascript
exports.api = function (req, res) {
  res.sendFile('u2f-api.js', {root: './scripts'});
};
````

The next two functions are pretty simple, and are there to check that the user has
authenticated with their password and to render the setup page for U2F:

````javascript
// check for auth then redirect to 2fa auth form
exports.twofacheck = function (req, res) {
  res.render('users/check2fa', {
    title: '2FA'
  });
};

// show setup 2fa form
exports.setup2fa = function (req, res) {
    res.render('users/setup2fa', {
        title: 'Setup 2FA'
  });
};
````

Now we are on to the actual registration page. Note that ````'/registerU2F'```` has a
controller for both GET and POST, ````users.registerGet```` and ````users.registerPost````:

````javascript
exports.registerGet = function (req, res) {
  try {
    var registerRequest = u2f.request(app_id);
    req.session.registerRequest = registerRequest;
    res.send(registerRequest);
  } catch (err) {
    console.log(err);
    res.status(400).send();
  }
};

exports.registerPost = function (req, res) {
  var registerResponse = req.body;
  var registerRequest = req.session.registerRequest;
  var id = req.user.id;

  try {
    var registration = u2f.checkRegistration(registerRequest,registerResponse);

    User.findById(id, function(err, user) {
      if (err) throw err;

      user.add2FA(registration, function(err, username) {
        if (err) throw err;
      });

      user.save({ validateBeforeSave: false }, function(err) {
        if (err) {
          throw err;
        }

      });
    });
    res.send();
  } catch (err) {
    console.log(err);
    res.status(400).send();
  }
};
````

The ````registerGet```` function is pretty simple, and simply provides the client side with
the ````app_id````. This should be set as a ````const```` in your main Javascript file, eg ````server.js````.
The ````app_id```` is simply the name of the site, which must be ````https```` in order for
the U2F library to accept it.

The ````registerPost```` function is slightly more complicated, because it handles the
receiving of the data needed to register the U2F device, as well as validating it and
adding it to the ````User```` schema. First, the request and response are parsed by the
Google U2F library with ````u2f.checkRegistration````. Then we look up the corresponding
user in our database, and call the ````add2FA```` function. This is a simple function which
goes in our ````app/models/user.js```` file, under the ````UserSchema.methods````:

````javascript
add2FA: function (registration) {
    this.deviceRegistration = registration;
  }
````

Then we save the user. Note that we do this without validating, which is not recommended.

Now that we are able to register a U2F device to a user server-side, lets allow them to
actually log in with it. We need to add the ````users.authenticateGet```` and ````users.authenticatePost````
methods to the ````app/controllers/users.js````:

````javascript
exports.authenticateGet = function (req, res) {
  User.findOne({username: req.user.username}, function(err, user){
    if (err) {
      res.status(400).send(err);
    } else {
      if (reg !== null) {
        var signRequest = u2f.request(app_id, user.deviceRegistration.keyHandle);
        req.session.signrequest = signRequest;
        req.session.deviceRegistration = user.deviceRegistration;
        res.send(signRequest);
      }
    }
  });
};

exports.authenticatePost = function (req, res) {
  var signResponse = req.body;
  var signRequest = req.session.signrequest;
  var deviceRegistration = req.session.deviceRegistration;
  try {
    var result = u2f.checkSignature(signRequest, signResponse, deviceRegistration.publicKey);
    if (result.successful) {
      req.session.secondFactor = 'u2f';
      res.send();
    } else {
      res.status(400).send();
    }
  } catch (err) {
    console.log(err);
    res.status(400).send();
  }
};
````

Our ````authenticateGet```` function simply checks for the user in the database, and uses
the stored ````deviceRegistration```` information to generate a ````signRequest```` with the
Google U2F API. It then sends the ````signRequest```` back to the client in the response.

Our ````authenticatePost```` function just uses the Google U2F library to check the signature
response with the request and the user's stored public key in the database. If the check is
successful then the session ````secondFactor```` flag is set, so we now know that the user has
successfully authenticated with their U2F device.

### Views

Finally, let's go over the views that we need to add for U2F to work. Unlike our Jade files
for password authentication, we need to use some client side Javascript to get retrieve the
keys off of the U2F device.

Here is the Jade portion of our ````setup2fa```` page located at ````app/views/users/setup2fa.jade````:

````
extends auth

block auth

  h1 2FA
  input(type='hidden' id='csrftoken_' name='_csrf', value="#{csrf_token}")
  p Welcome to the 2FA Demo. Now you get to set up the 2FA methods
  p
    | Once you have set your token sucessfully you can
    a(href='/logout') logout
    |  and then try and log back in
  p
  h2 Fido U2F
  p Plug your token in and press the button below and follow the instructions
  button#setupFido Fido U2F

  div
    h3 Console
    div(id="workspace")

  script(type='application/javascript').
    // javascript goes here
  script(src='u2f-api.js')
````

Note that we once again include the hidden CSRF field. This time we will handle sending
that token directly within the embedded Javascript on the page. The Javascript that is
embedded in this page is as follows:

````javascript
function clearWorkspace() {
      var element = document.getElementById('workspace');
      while (element.firstChild) {
        element.removeChild(element.firstChild);
      }
    }

    var xhr = new XMLHttpRequest();

    var fidoButton = document.getElementById('setupFido');
    fidoButton.onclick = function setupFido() {
      clearWorkspace();
      xhr.open('GET', '/registerU2F', true);
      xhr.onreadystatechange = function () {
        if(xhr.readyState == 4 && xhr.status == 200) {
          var registerRequest = [JSON.parse(xhr.responseText)];
          document.getElementById('workspace').innerHTML ="If your token has a button, press it when the light flashes";
          u2f.register(registerRequest,[], function(data){
            var xhr2 = new XMLHttpRequest();
            xhr2.open('POST', '/registerU2F', true);
            xhr2.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
            xhr2.onreadystatechange = function() {
              if (xhr2.readyState == 4 && xhr2.status == 200) {
                document.getElementById('workspace').innerHTML ="Fido U2F Token enabled";
              } else if (xhr2.readyState == 4 && xhr2.status !== 200) {
                document.getElementById('workspace').innerHTML ="error setting up Fido U2F token";
              }
            }
            var csrftoken = document.getElementById('csrftoken_').value;
            var jsonData = JSON.parse(JSON.stringify(data));
            jsonData._csrf = csrftoken;

            xhr2.send(JSON.stringify(jsonData));
          });
        }
      };
      xhr.send();
    }
  ````
  It is important to note that indentation matters in Jade, so this javascript must be
  indented so that is within the javascript block as well as within ````block auth````.
  You can check the full example at the Github link provided.

  The ````workspace```` referred to in this script is simply an area on the page that we can
  change dynamically in order to update the user on the process of registering their token.
  The next step is run once the user presses the button. It then sends a HTTP GET request to   ````/regisgterU2F```` (which we have already prepared for server side). This will respond
  with the ````signRequest```` which we can then use to call the ````register()```` function
  from the Google U2F API. The ````register()```` function requires the user to interact
  with the U2F device, so we prompt the user to touch the device when it flashes. The script
  then adds the ````csrftoken_```` to the data to be sent to the server and
  sends a POST with the ````signResponse````. It will then tell the user if the registration
  process was successful by checking the response status.

  Now let's look at the similar ````check2fa.jade```` file and the accompanying Javascript:

  ````
  extends auth

block auth
  .text-center
    h1 Connect your token provider, then press the button to continue
    input(type='hidden' id='csrftoken_' name='_csrf', value="#{csrf_token}")

    button#fidoButton FIDO U2F

    div(id="fido")
      p If the light flashes on your token please press the button
  script(src='u2f-api.js', type='text/javascript')
  script(type='text/javascript').
    // insert javascript here
  ````

  ````javascript
  var fidoButton = document.getElementById('fidoButton');
    fidoButton.onclick = function() {
      document.getElementById('fido').style.visibility = "visible";
      var xhr = new XMLHttpRequest();
      xhr.open('GET', '/authenticateU2F', true);
      xhr.onreadystatechange = function() {
        if (xhr.readyState == 4 && xhr.status == 200) {
        var signRequests = [JSON.parse(xhr.responseText)];
        console.log(signRequests[0]);
        try {
          u2f.sign(signRequests,function(data){
            if (!data.errorCode) {
              var xhr2 = new XMLHttpRequest();
              xhr2.open('POST', '/authenticateU2F', true);
              xhr2.setRequestHeader("Content-Type", "application/json;charset=UTF-8");
              xhr2.onreadystatechange = function() {
                if (xhr2.readyState == 4 && xhr2.status == 200) {
                  //redirect to /user
                  window.location = '/';
                } else if (xhr2.readyState == 4 && xhr2.status !== 200) {
                  //redirect to /logout
                  //window.location = '/logout';
                  console.log("failed");
                }
              };
              var csrftoken = document.getElementById('csrftoken_').value;
              var jsonData = JSON.parse(JSON.stringify(data));
              jsonData._csrf = csrftoken;

              xhr2.send(JSON.stringify(jsonData));
            } else {
              document.getElementById('fido').innerHTML = "Token error: " + data.errorMessage;
            }
          },3000);
        } catch (err) {
          console.log("Catch err - " + err );
        }
      }
    }
    xhr.send();
    }
  ````

  The Jade here is pretty similar and self explanatory. The Javascript will execute on button
  click, and submits a GET request which will return the ````signRequest````. We can then use
  the Google U2F library to generate the signature, which will once again require the user to
  touch the device. Once we have generated the signature, we send it in the POST request
  along with the CSRF token.

  That covers all of the essentials! If you hare having trouble getting the full picture,
  check out the Github page to see how all of the pieces fit together.

## Notes

This tutorial is a constant work in progress. We are aware that there are probably better
ways to do things, and we encourage the community to help us make this tutorial as helpful
as possible. If you know a way to do something better, or you see a vulnerability, please
submit a pull request!

## Credits

The site this tutorial is based on is itself the product of following multiple tutorials and
combining different pieces of code. I will try to list them here:
* Boilerplate example code for an Express + Passport site: https://github.com/madhums/node-express-mongoose/
  * accompanying tutorial https://github.com/madhums/node-express-mongoose/wiki
  * full example: https://github.com/madhums/node-express-mongoose-demo/
* Tutorial for using 2Factor with Express http://www.hardill.me.uk/wordpress/tag/passportjs/
  * Example Code https://github.com/madhums/node-express-mongoose/
