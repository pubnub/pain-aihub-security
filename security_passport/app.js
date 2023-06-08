const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const { MongoClient, ObjectId } = require('mongodb');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const User = require('./models/user');
const bcrypt = require('bcryptjs');


const uri = 'mongodb://pnuser:supersecurepassword@database_mongo_2:27017';

async function getDb() {
  const client = await MongoClient.connect(uri, { useNewUrlParser: true, useUnifiedTopology: true });
  return client.db('test');
}

const app = express();

app.use(bodyParser.urlencoded({ extended: false }));
app.use(session({ secret: 'secret', resave: false, saveUninitialized: false }));
app.use(passport.initialize());
app.use(passport.session());

passport.use('local', new LocalStrategy({
  usernameField: 'username',
  passwordField: 'password',
}, async (username, password, done) => {
  const db = await getDb();
  const user = await db.collection('users').findOne({ username: username });

  if (!user) {
    return done(null, false, { message: 'No user found.' });
  }

  const isValid = await bcrypt.compare(password, user.password);
  if (!isValid) {
    return done(null, false, { message: 'Wrong password.' });
  }

  return done(null, user);
}));

passport.serializeUser(function(user, done) {
  done(null, user._id);
});

passport.deserializeUser(async function(id, done) {
  const db = await getDb();
  const user = await db.collection('users').findOne({ _id: new ObjectId(id) });
  done(null, user);
});

function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) {
    return next();
  }
  res.redirect('/unauthorized');
}

app.get('/', (req, res) => {
  res.send('Home page. Please <a href="/login">log in</a>.');
});

app.get('/login', (req, res) => {
  res.send(`
    <form action="/login" method="post">
      <div>
        <label>Username:</label>
        <input type="text" name="username"/>
      </div>
      <div>
        <label>Password:</label>
        <input type="password" name="password"/>
      </div>
      <div>
        <input type="submit" value="Log In"/>
      </div>
    </form>
  `);
});

app.post('/login', passport.authenticate('local', { failureRedirect: '/login' }), (req, res) => {
  res.redirect('/secret');
});

app.get('/signup', (req, res) => {
  res.send(`
    <form action="/signup" method="post">
      <div>
        <label>Username:</label>
        <input type="text" name="username"/>
      </div>
      <div>
        <label>Password:</label>
        <input type="password" name="password"/>
      </div>
      <div>
        <input type="submit" value="Sign Up"/>
      </div>
    </form>
  `);
});

app.post('/signup', async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.password, 10);
    const user = { username: req.body.username, password: hashedPassword };
    const db = await getDb();
    await db.collection('users').insertOne(user);
    res.redirect('/login');
  } catch {
    res.redirect('/signup');
  }
});

app.get('/secret', ensureAuthenticated, (req, res) => {
  res.send('Welcome to the secret page, ' + req.user.username);
});

app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});

app.get('/unauthorized', (req, res) => {
  res.send('You are not authorized to view this page. Please <a href="/login">log in</a>.');
});

app.listen(5001, () => {
  console.log('App listening on port 5001!');
});

