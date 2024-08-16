const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bodyParser = require('body-parser');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcrypt');
const CryptoJS = require('crypto-js');
const { body, validationResult } = require('express-validator');
const validator = require('validator');
const app = express();
const port = 3000;

app.use(express.static(__dirname + '/public'));

// Set up the database
const db = new sqlite3.Database('./passwords.db');

// Create users and passwords tables if they don't exist
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password TEXT
  )`);
  
  db.run(`CREATE TABLE IF NOT EXISTS passwords (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    website TEXT,
    username TEXT,
    password TEXT,
    FOREIGN KEY(user_id) REFERENCES users(id)
  )`);
});

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: './' }),
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: { 
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 // 1 day
  }
}));

app.set('view engine', 'ejs');

const encryptionKey = process.env.ENCRYPTION_KEY || 'your-secret-encryption-key';

// Middleware for input sanitization
const sanitizeInputs = (req, res, next) => {
  for (let key in req.body) {
    if (typeof req.body[key] === 'string') {
      req.body[key] = validator.escape(req.body[key].trim());
    }
  }
  next();
};

app.use(sanitizeInputs);

// Password strength check
function isPasswordStrong(password) {
  const minLength = 8;
  const hasUpperCase = /[A-Z]/.test(password);
  const hasLowerCase = /[a-z]/.test(password);
  const hasNumbers = /\d/.test(password);
  const hasNonalphas = /\W/.test(password);
  return password.length >= minLength && hasUpperCase && hasLowerCase && hasNumbers && hasNonalphas;
}

// Generate random password
function generateRandomPassword(length = 12) {
  const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+~`|}{[]:;?><,./-=";
  let password = "";
  for (let i = 0; i < length; i++) {
    password += charset.charAt(Math.floor(Math.random() * charset.length));
  }
  return password;
}

// Routes
app.get('/', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }
  db.all('SELECT * FROM passwords WHERE user_id = ?', [req.session.user.id], (err, passwords) => {
    if (err) {
      return res.status(500).send('Error occurred');
    }
    const decryptedPasswords = passwords.map(pw => ({
      ...pw,
      password: CryptoJS.AES.decrypt(pw.password, encryptionKey).toString(CryptoJS.enc.Utf8)
    }));
    res.render('home', { user: req.session.user, passwords: decryptedPasswords });
  });
});

app.get('/login', (req, res) => {
  res.render('login');
});

app.post('/login', [
  body('email').isEmail().normalizeEmail(),
  body('password').notEmpty(),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { email, password } = req.body;
  
  db.get('SELECT * FROM users WHERE email = ?', [email], (err, user) => {
    if (err) {
      return res.status(500).send('Error occurred');
    }
    if (!user) {
      return res.status(400).send('User not found');
    }
    bcrypt.compare(password, user.password, (err, result) => {
      if (result) {
        req.session.user = { id: user.id, username: user.username, email: user.email };
        res.redirect('/');
      } else {
        res.status(400).send('Incorrect password');
      }
    });
  });
});

app.get('/register', (req, res) => {
  res.render('register');
});

app.post('/register', [
  body('username').isLength({ min: 3 }).trim().escape(),
  body('email').isEmail().normalizeEmail(),
  body('password').custom(value => {
    if (!isPasswordStrong(value)) {
      throw new Error('Password does not meet strength requirements');
    }
    return true;
  }),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  const { username, email, password } = req.body;
  
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) {
      return res.status(500).send('Error occurred');
    }
    db.run('INSERT INTO users (username, email, password) VALUES (?, ?, ?)', [username, email, hash], (err) => {
      if (err) {
        return res.status(400).send('Username or email already exists');
      }
      res.redirect('/login');
    });
  });
});

app.post('/add-credentials', [
  body('site').notEmpty().trim().escape(),
  body('username').notEmpty().trim().escape(),
  body('password').notEmpty(),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  if (!req.session.user) {
    return res.status(401).send('Unauthorized');
  }
  const { site, username, password } = req.body;
  const encryptedPassword = CryptoJS.AES.encrypt(password, encryptionKey).toString();
  
  db.run('INSERT INTO passwords (user_id, website, username, password) VALUES (?, ?, ?, ?)',
    [req.session.user.id, site, username, encryptedPassword],
    (err) => {
      if (err) {
        return res.status(500).send('Error occurred');
      }
      res.redirect('/');
    }
  );
});

app.post('/change-password', [
  body('currentPassword').notEmpty(),
  body('newPassword').custom(value => {
    if (!isPasswordStrong(value)) {
      throw new Error('New password does not meet strength requirements');
    }
    return true;
  }),
], (req, res) => {
  const errors = validationResult(req);
  if (!errors.isEmpty()) {
    return res.status(400).json({ errors: errors.array() });
  }

  if (!req.session.user) {
    return res.status(401).send('Unauthorized');
  }
  
  const { currentPassword, newPassword } = req.body;
  
  db.get('SELECT * FROM users WHERE id = ?', [req.session.user.id], (err, user) => {
    if (err) {
      return res.status(500).send('Error occurred');
    }
    
    bcrypt.compare(currentPassword, user.password, (err, result) => {
      if (result) {
        bcrypt.hash(newPassword, 10, (err, hash) => {
          if (err) {
            return res.status(500).send('Error occurred');
          }
          db.run('UPDATE users SET password = ? WHERE id = ?', [hash, req.session.user.id], (err) => {
            if (err) {
              return res.status(500).send('Error occurred');
            }
            res.send('Password updated successfully');
          });
        });
      } else {
        res.status(400).send('Incorrect current password');
      }
    });
  });
});

app.get('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      return res.status(500).send('Error occurred');
    }
    res.redirect('/login');
  });
});

app.get('/generate-password', (req, res) => {
  const password = generateRandomPassword();
  res.json({ password });
});

app.listen(port, () => {
  console.log(`Password manager running at http://localhost:${port}`);
});