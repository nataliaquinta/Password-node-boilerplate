const LocalStrategy = require('passport-local').Strategy;
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs'); //to decrypt the hash and compare the passwords

//load user model
const User = require('../models/User');

  module.exports = function(passport) {
      passport.use(
          new LocalStrategy({usernameField: 'email'}, (email, password, done)=> {
              //match the input username (email) with db email 
              User.findOne({email:email})
              .then(user=> {
                  if(!user) {
                      return done(null, false, {message: 'This email is not registered'});
                  }
                  //match the password (first bcrypt because the user.password is hashed)
                  bcrypt.compare(password, user.password, (err, isMatch) => {
                      if(err) throw err;
                      if(isMatch) {
                          return done(null, user);
                      } else {
                          return done(null, false, {message: 'Password incorrect'});
                      }
                  });
              })
              .catch(err => console.log(err));
          })
      );

      //methods to serialize and deserialize the user
      passport.serializeUser((user, done) => {
        done(null, user.id);
      });
      
      passport.deserializeUser((id, done) => {
        User.findById(id, function(err, user) {
          done(err, user);
        });
      });

  }