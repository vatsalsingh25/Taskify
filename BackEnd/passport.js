const passport = require("passport");
require("dotenv").config();

const LocalStrategy = require("passport-local").Strategy;
const authModel = require("./Models/Model");
const bcrypt = require("bcrypt");


const callback = async function (accessToken, refreshToken, profile, cb) {
  // console.log(profile);
  const newUser = {
    userName: profile.displayName,
    email: profile.emails[0].value,
    googleId: profile.id,
    picUrl: profile.photos[0].value,
  };
  try {
    const user = await authModel.findOne({ googleId: profile.id });
    if (user) return cb(null, user);
    else {
      const savedUser = await authModel(newUser).save();
      return cb(null, savedUser);
    }
  } catch (err) {
    return cb(err);
  }
};

const callback2 = async function (accessToken, refreshToken, profile, cb) {
  console.log(profile);
  const newUser = {
    userName: profile.displayName,
    fbId: profile.id,
    email: profile.emails[0].value,
    picUrl: profile.photos[0].value,
  };
  try {
    const user = await authModel.findOne({ fbId: profile.id });
    if (user) return cb(null, user);
    else {
      const savedUser = await authModel(newUser).save();
      return cb(null, savedUser);
    }
  } catch (err) {
    return cb(err);
  }
};
const LocalStrategycallback = (email, password, done) => {
  authModel
    .findOne({ email: email })
    .then((user) => {
      if (!user) {
        return done(null, false);
      }
      const isValid = bcrypt.compare(password, user.password);
      isValid.then((val) => {
        if (val) return done(null, user);
        return done(null, false, { message: "incorrect password" });
      });
    })
    .catch((err) => {
      return done(err);
    });
};

passport.use(
  new LocalStrategy({ usernameField: "email" }, LocalStrategycallback)
);

// //Serializing and Deserializing
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser((userId, done) => {
  authModel
    .findById(userId)
    .then((user) => {
      done(null, user);
    })
    .catch((err) => {
      done(err);
    });
  // return done(null, id);
});
