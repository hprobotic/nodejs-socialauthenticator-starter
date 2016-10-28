"use strict"
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('mongoose').model('User');
const passportLocalStrategy = require('passport-local').Strategy;

module.exports = function(config) {

    return new passportLocalStrategy({
        usernameField: 'email',
        passwordField: 'password',
        session: false,
        passReqToCallback: true
    }, function(req, email, password, done) {
        let userData = {
            email: email.trim(),
            password: password.trim(),
        };

        // find a user by email address
        User.findOne({email: userData.email}, function(err, user) {
            if (err) { return done(err); }

            if (!user) {
                let error = new Error("Incorrect email or password");
                error.name = "IncorrectCredentialsError";
                return done(error);
            }

            // check if a hashed user's password is equal to a value saved in the database
            user.comparePassword(userData.password, function(err, isMatch) {
                if (err) { return done(err); }

                if (!isMatch) {
                    let error = new Error("Incorrect email or password");
                    error.name = "IncorrectCredentialsError";
                    return done(error);
                }


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
    });

};