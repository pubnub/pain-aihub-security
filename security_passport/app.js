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
  usernameField: 'email',
  passwordField: 'password',
}, async (email, password, done) => {
  const db = await getDb();
  const user = await db.collection('users').findOne({ email: email });

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

function ensureAdmin(req, res, next) {
  if (req.isAuthenticated() && req.user.isAdmin) {
    return next();
  }
  res.redirect('/unauthorized');
}

app.get('/', (req, res) => {
  res.send('Home page. Please <a href="/login">log in</a>.');
});

app.get('/signup', (req, res) => {
  res.send(`
    <form action="/signup" method="post">
      <div>
        <label>Username:</label>
        <input type="text" name="username"/>
      </div>
      <div>
        <label>Email:</label>
        <input type="email" name="email"/>
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
    const user = { 
      email: req.body.email, 
      password: hashedPassword, 
      created_at: new Date(), 
      updated_at: new Date() 
    };
    const db = await getDb();
    await db.collection('users').insertOne(user);
    res.redirect('/login');
  } catch {
    res.redirect('/signup');
  }
});


app.get('/login', (req, res) => {
  res.send(`
    <form action="/login" method="post">
      <div>
        <label>Email:</label>
        <input type="text" name="email"/>
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

app.post('/update_password', ensureAuthenticated, async (req, res) => {
  try {
    const hashedPassword = await bcrypt.hash(req.body.new_password, 10);
    const db = await getDb();
    await db.collection('users').updateOne(
      { _id: new ObjectId(req.user._id) },
      { 
        $set: { 
          password: hashedPassword, 
          updated_at: new Date() 
        }
      }
    );
    res.redirect('/profile');
  } catch {
    res.redirect('/change_password');
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

// Admin routes
app.get('/admin/users', ensureAuthenticated, ensureAdmin, async (req, res) => {
  const db = await getDb();
  const users = await db.collection('users').find({}).toArray();
  res.json(users);
});

app.post('/admin/users', ensureAuthenticated, ensureAdmin, async (req, res) => {
  const hashedPassword = await bcrypt.hash(req.body.password, 10);
  const user = { 
    email: req.body.email, 
    password: hashedPassword, 
    created_at: new Date(), 
    updated_at: new Date() 
  };
  const db = await getDb();
  await db.collection('users').insertOne(user);
  res.redirect('/admin/users');
});

app.put('/admin/users/:id', ensureAuthenticated, ensureAdmin, async (req, res) => {
  const hashedPassword = await bcrypt.hash(req.body.password, 10);
  const user = { 
    email: req.body.email, 
    password: hashedPassword, 
    updated_at: new Date() 
  };
  const db = await getDb();
  await db.collection('users').updateOne({ _id: new ObjectId(req.params.id) }, { $set: user });
  res.redirect('/admin/users');
});

app.delete('/admin/users/:id', ensureAuthenticated, ensureAdmin, async (req, res) => {
  const db = await getDb();
  await db.collection('users').deleteOne({ _id: new ObjectId(req.params.id) });
  res.redirect('/admin/users');
});

app.listen(5001, () => {
  console.log('App listening on port 5001!');
});

