const express = require('express');
const app = express();
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const bcrypt = require('bcrypt');
const { name } = require('ejs');

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');

const db = new sqlite3.Database('./main.db', sqlite3.OPEN_READWRITE, (err) => {
  if (err) return console.error(err.message);
  console.log("Connected to database.");
});


app.get('/', (req, res) => {
  const error = req.query.error;
  res.render('login', { error });
});

app.post('/signup', async (req, res) => {
  const { Username, email, password } = req.body;

  if (!Username || !email || !password) {
    return res.status(400).send("All fields are required.");
  }

  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const sql = `INSERT INTO users (name, email, password) VALUES (?, ?, ?)`;
    db.run(sql, [Username, email, hashedPassword], function (err) {
      if (err) {
        if (err.message.includes("UNIQUE constraint failed")) {
          return res.status(400).send("Email already exists.");
        }
        console.error(err.message);
        return res.status(500).send("Failed to create account.");
      }
      res.redirect('/');
    });
  } catch (error) {
    console.error(error);
    res.status(500).send("Internal server error");
  }
});


app.post('/index', (req, res) => {
  const { email, password } = req.body;

  const sql = `SELECT * FROM users`;
  db.get(sql, [name,email], async (err, row) => {
    if (err) {
      return res.status(500).send("Server error");
    }

    if (!row) {
      return res.redirect('/?error=' + encodeURIComponent("Invalid email or password"));
    }

    const match = await bcrypt.compare(password, row.password);
    if (match) {
      res.render('profile', { user: row });
    } else {
      return res.redirect('/?error=' + encodeURIComponent("Invalid email or password"));
    }
  });
});

const PORT = 5500;
app.listen(PORT, () => {
  console.log(`Server running at http://localhost:${PORT}`);
});
