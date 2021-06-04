require('dotenv').config()
const express = require("express");
const path = require("path");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
const mongoose = require("mongoose");
const Schema = mongoose.Schema;
const bcrypt = require('bcryptjs');

const mongoDb = process.env.MONGO_URI;
mongoose.connect(mongoDb, { useUnifiedTopology: true, useNewUrlParser: true });
const db = mongoose.connection;
db.on("error", console.error.bind(console, "mongo connection error"));

const User = mongoose.model(
  "User",
  new Schema({
    username: { type: String, required: true },
    password: { type: String, required: true }
  })
);

const app = express();
app.set('views', path.join(__dirname, 'views'));
app.set("view engine", "ejs");

app.use(session({ secret: "cats", resave: false, saveUninitialized: true }));
app.use(passport.initialize());
app.use(passport.session());
app.use(express.urlencoded({ extended: false }));

app.use(function(req, res, next) {
  res.locals.currentUser = req.user;
  next();
}); // gives access to currentUser variables in all the views (don't have to manually pass into controllers)

app.get("/", (req, res) => {
  res.render("index", { user: req.user });
});


app.get("/sign-up", (req, res) => res.render("sign_up_form"));

app.post("/sign-up", function(req, res, next){
  bcrypt.hash(req.body.password, 10, (err, hashedPassword) =>{
    const user = new User({
      username: req.body.username, 
      password: hashedPassword
    }).save(err => {
      if (err) {
        return next(err)
      }
    })
  })
  res.redirect('/')
})

passport.use( // call when using passport.authentication()
  new LocalStrategy((username, password, done) => {
    User.findOne({ username: username }, (err, user) => {
      if (err) { 
        return done(err);
      }
      if (!user) {
        return done(null, false, { message: "Incorrect username" });
      }
      bcrypt.compare(password, user.password, (err, res) => {
        if (res) {
          // passwords match! log user in
          return done(null, user)
        } else {
          // passwords do not match!
          return done(null, false, { message: "Incorrect password" })
        }
      })
    });
  })
); // takes user + pw, tries to find user in DB, then makes sure pw match

// cookie is created and stored in user browser to allow user to stay logged in
passport.serializeUser(function(user, done) {
  done(null, user.id);
});

passport.deserializeUser(function(id, done) {
  User.findById(id, function(err, user) {
    done(err, user);
  });
});
// these 2 functions define information passport is looking for when it creates and decodes the cookie

app.post(
  "/log-in",
  passport.authenticate("local", {
    successRedirect: "/",
    failureRedirect: "/"
  })
); // looks at request body for parameters named username and password, then runs LocalStrategy function
// to see if username and password are in the database
// then, creates session cookie (stored in user's browser) can access later to see if user logged in
// can also redirect to different routes based on whether login is success or failure

app.get("/log-out", (req, res) => {
  req.logout();
  res.redirect("/");
});

app.listen(3000, () => console.log("app listening on port 3000!"));


