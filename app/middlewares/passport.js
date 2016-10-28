let passport = require('passport')
let wrap = require('nodeifyit')
let User = require('../models/user')
let LocalStrategy = require('passport-local')
let localSigninStrategy = require('./local-signin')
let localSignupStrategy = require('./local-signup')
let FacebookStrategy = require('passport-facebook')
// Handlers
async function localAuthHandler(email, password) {
  let user = await User.promise.findOne({email})

  if (!user || email !== user.email) {
    return [false, {message: 'Invalid username'}]
  }

  if (!await user.validatePassword(password)) {
    return [false, {message: 'Invalid password'}]
  }
  return user
}

async function localSignupHandler(email, password) {
  email = (email || '').toLowerCase()
  // Is the email taken?
  if (await User.promise.findOne({email})) {
    return [false, {message: 'That email is already taken.'}]
  }

  // create the user
  let user = new User()
  user.email = email
  // Use a password hash instead of plain-text
  user.password = await user.generateHash(password)
  return await user.save()
}

// 3rd-party Auth Helper
function loadPassportStrategy(OauthStrategy, config, userField) {
  config.passReqToCallback = true
  passport.use(new OauthStrategy(config, wrap(authCB, {spread: true})))

  async function authCB(req, token, _ignored_, account) {
      // 1. Load user from store by matching user[userField].id && account.id
      // 2. If req.user exists, we're authorizing (linking account to an existing user)
      // 2a. Ensure it's not already associated with another user
      // 2b. Link account
      // 3. If req.user !exist, we're authenticating (logging in an existing user)
      // 3a. If Step 1 failed (existing user for 3rd party account does not already exist), create a user and link this account (Otherwise, user is logging in).
      // 3c. Return user
  }
}

function configure(CONFIG) {
  // Required for session support / persistent login sessions
  passport.serializeUser(wrap(async (user) => user._id))
  passport.deserializeUser(wrap(async (id) => {
    return await User.promise.findById(id)
  }))

  /**
   * Local Auth
   */
  // let localLoginStrategy = new LocalStrategy({
  //   usernameField: 'email', // Use "email" instead of "username"
  //   failureFlash: true // Enable session-based error logging
  // }, wrap(localAuthHandler, {spread: true}))
  //
  // let localSignupStrategy = new LocalStrategy({
  //   usernameField: 'email',
  //   failureFlash: true
  // }, wrap(localSignupHandler, {spread: true}))

// 3rd-party Auth Helper
  function loadPassportStrategy(OauthStrategy, config, userField) {
    config.passReqToCallback = true
    passport.use(new OauthStrategy(config, wrap(authCB, { spread: true })))

    async function authCB(req, token, _ignored_, account) {
      let accountId = userField + '.id';

      let user
      console.log(req.user)
      if (req.user) {
        user = await User.promise.findById(req.user.id)
      } else {
        user = null
      }

      if (!user) user = new User();

      user[userField].id = user.facebook.id;
      user[userField].token = user.facebook.token;
      user[userField].secret = _ignored_;
      user[userField].name = user.facebook.name;
      user[userField].email = "test@gmail.com";

      return await user.save();
    }
  }
  passport.use('local-login', localSigninStrategy)
  passport.use('local-signup', localSignupStrategy)

  /**
   * 3rd-Party Auth
   */
  loadPassportStrategy(FacebookStrategy, {
    clientID: "1850049045215527",
    clientSecret: "34c8cceaf5dfe6c5f93bfe5051eff995",
    callbackURL: "http://socialauthenticator.com:8000/auth/facebook/callback"
  }, 'facebook')


  return passport
}

module.exports = {passport, configure}
