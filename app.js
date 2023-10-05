require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require("mongoose");
const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local");
const bcrypt = require("bcrypt");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const FacebookStrategy = require("passport-facebook").Strategy;
const app = express();
app.set("view engine", "ejs");

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use((err, req, res, next) => {
  console.error(err.stack); // Log the error for debugging (remove in production)

  // Render a friendly error page with a status code of 500 (Internal Server Error)
  res.status(500).render("error", {
    message: "Something went wrong. Please try again later.",
  });
});

// Connect to MongoDB
async function connectToMongodb() {
  try {
    const localUrl = "mongodb://127.0.0.1:27017/serectDB";
    const url = process.env.MONDO_DB_URL;
    await mongoose.connect(localUrl);
    console.log("\nScussfully connect to the mongoDB server\n");
    app.listen(process.env.PORT || 3000, function () {
      console.log("Server started on port 3000");
    });
  } catch (error) {
    console.log("\nConnection faild => " + error + "\n");
  }
}

connectToMongodb();
// Initialize Express session
app.use(
  session({
    secret: process.env.SECRET_KEY,
    resave: false,
    saveUninitialized: false,
  })
);

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Define the user
const secretsSchema = new mongoose.Schema({
  _id: String,
  secrets: [String],
});
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  googleId: String,
  facebookID: String,
});
userSchema.index(
  {
    googleId: 1,
    facebookID: 1,
    username: 1,
  },
  {
    unique: true,
    partialFilterExpression: {
      googleId: { $type: "string" },
      facebookID: { $type: "string" },
      username: { $type: "string" },
    },
  }
);
// Create the User model
const User = mongoose.model("User", userSchema);
const Secrets = mongoose.model("Secret", secretsSchema);

// Configure Passport to serialize and deserialize User
passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

app.use((req, res, next) => {
  res.locals.req = req;
  next();
});

//google stratergy start
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL:
        "https://busy-tan-cricket-slip.cyclic.app/auth/google/secrets",
      passReqToCallback: true, // Pass the req object to the callback
    },
    async (req, accessToken, refreshToken, profile, done) => {
      try {
        // Check if a user with the given Google ID exists in your database
        let user = await User.findOne({ googleId: profile.id });

        if (!user) {
          // User doesn't exist in the database, create a new user
          user = new User({
            googleId: profile.id,
          });

          await user.save();
        }

        // Log in the user
        req.login(user, (err) => {
          if (err) {
            return done(err);
          }

          done(null, user);
        });
      } catch (err) {
        done(err);
      }
    }
  )
);

//facebook stratergy start **
passport.use(
  new FacebookStrategy(
    {
      clientID: process.env.FACEBOOK_APP_ID,
      clientSecret: process.env.FACEBOOK_APP_SECRET,
      callbackURL: "https://busy-tan-cricket-slip.cyclic.app/facebook/secrets",
      passReqToCallback: true,
    },
    async function (req, accessToken, refreshToken, profile, done) {
      try {
        // Check if a user with the given Google ID exists in your database
        let user = await User.findOne({ facebookID: profile.id });

        if (!user) {
          // User doesn't exist in the database, create a new user
          user = new User({
            facebookID: profile.id,
          });

          await user.save();
        }

        // Log in the user
        req.login(user, (err) => {
          if (err) {
            return done(err);
          }

          done(null, user);
        });
      } catch (err) {
        done(err);
      }
    }
  )
);

// Configure Passport to use the local strategy
passport.use(
  new LocalStrategy(async (username, password, done) => {
    try {
      const user = await User.findOne({ username: username });
      if (!user) {
        return done(null, false, { message: "No user found" });
      }

      const passwordMatch = await bcrypt.compare(password, user.password);
      if (!passwordMatch) {
        return done(null, false, { message: "Incorrect password" });
      }

      return done(null, user);
    } catch (err) {
      return done(err);
    }
  })
);
//prompt:consent will force goodle to open signup google window every time hit the continue with google
app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile"], prompt: "consent" })
);

// Google callback route (the URL specified in the Google API Console)
app.get(
  "/auth/google/secrets",
  passport.authenticate("google", { failureRedirect: "/" }),
  (req, res) => {
    // Successful authentication, redirect to a success page
    res.redirect("/secrets");
  }
);

//When user press login with facebook this will trigger
app.get(
  "/auth/facebook",
  passport.authenticate("facebook", {
    scope: ["email"],
    prompt: "consent",
  })
);

// Facebook callback route (the URL specified in the Google API Console)

app.get(
  "/auth/facebook/secrets",
  passport.authenticate("facebook", {
    failureRedirect: "/",
    failureMessage: true,
  }),
  function (req, res) {
    // Successful authentication, redirect to a success page
    res.redirect("/secrets");
  }
);

app.get("/", function (req, res) {
  if (req.isAuthenticated()) {
    return res.redirect("/secrets");
  }
  res.render("index");
});

//This is use to handle the call back from facebook
app.get(
  "/oauth2/redirect/facebook",
  passport.authenticate("facebook", {
    failureRedirect: "/login",
    failureMessage: true,
  }),
  function (req, res) {
    res.redirect("/");
  }
);

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect("/");
}

app.get("/secrets", ensureAuthenticated, async function (req, res) {
  try {
    const users = await Secrets.find({}); // Retrieve all users from the database
    console.log(users);
    res.render("secrets", { users: users });
  } catch {
    console.log("error occur in finding a user");
  }
});

app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/");
  }
});

app.post("/submit", async function (req, res) {
  console.log(req.user.id);

  const userId = req.user.id;
  const secret = req.body.secret;
  console.log(secret);

  // Function to add a secret for a user

  try {
    // Check if the user exists in the secrets collection
    const existingSecret = await Secrets.findOne({ _id: userId });

    if (!existingSecret) {
      // If the user doesn't exist, create a new entry
      const newEntry = new Secrets({
        _id: userId,
        secrets: [secret],
      });

      await newEntry.save();
      res.redirect("/secrets");
    } else {
      // If the user exists, append the new secret to their array
      existingSecret.secrets.push(secret);
      await existingSecret.save();
      res.redirect("/secrets");
    }
  } catch (error) {
    console.log(`Error occuer in adding secret ${error}`);
    res.redirect("/secrets");
  }

  // Example usage:
});

app.post("/register", async function (req, res) {
  const email = req.body.username;
  const password = req.body.password;

  const user = await User.findOne({ username: email });
  //if user already in database redirect himto log in
  if (user) {
    res.redirect("/?userExists=true");
  } else {
    try {
      // Hash and salt the password before saving it
      bcrypt.hash(password, 10, async (err, hashedPassword) => {
        if (err) {
          throw err;
        }

        const newUser = new User({ username: email, password: hashedPassword });
        req.login(newUser, (loginErr) => {
          if (loginErr) {
            // Handle login error, if any
            console.log(loginErr);
          }
        });
        await newUser.save();
        console.log("User registerd");

        res.redirect("/secrets");
      });
    } catch (error) {
      console.log(error);
      res.redirect("/register");
    }
  }
});

app.post("/login", (req, res, next) => {
  console.log("Login is triggered");
  passport.authenticate("local", (err, user, info) => {
    if (err) {
      // Handle unexpected errors (e.g., database errors)
      console.log("***Unexpeted error occur in log in " + err);
      return res.redirect("/login");
    }

    if (!user) {
      // Authentication failed: user not found or incorrect password
      // You can access the failure reason in the `info` object
      if (info && info.message === "No user found") {
        // Email not found in the database, you can choose to register here
        console.log("No user found please register");
        return res.redirect("/?noUserFound=true");
      } else if (info && info.message === "Incorrect password") {
        // Incorrect password, let the user know
        console.log("incorrect password");
        return res.redirect("/?passWordIncorrect=true");
      }
    }

    // If the code reaches here, it means authentication succeeded
    req.login(user, (loginErr) => {
      if (loginErr) {
        // Handle login error, if any
        console.log(loginErr);
        return next(loginErr);
      }
      return res.redirect("/secrets"); // Redirect to a protected page on success
    });
  })(req, res, next);
});

app.get("/logout", function (req, res) {
  req.logout(function (err) {
    if (err) {
      // Handle any errors that occur during logout
      console.error(err);
      return next(err);
    }
    res.redirect("/");
  });
});
