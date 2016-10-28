"use strict"
const User = require('mongoose').model('User');
const jwt = require('jsonwebtoken');
const passportLocalStrategy = require('passport-local').Strategy;


module.exports = function(config) {

    /**
     * Return the Passport Local Strategy object.
     */
    return new passportLocalStrategy({
        usernameField: 'email',
        passwordField: 'password',
        session: false,
        passReqToCallback: true
    }, function(req, email, password, done) {
        let userData = {
            email: email.trim(),
            password: password.trim(),
            name: req.body.name.trim()
        };

        let newUser = new User(userData);
        newUser.save(function(err, user) {
            if (err) { return done(err); }

            let payload = {
                sub: user._id,
                name: user.name,
                email: user.email
            };

            // create a token string
            let token = jwt.sign(payload, process.env.jwtSecret);
            return done(null, token);
        });
    });

};