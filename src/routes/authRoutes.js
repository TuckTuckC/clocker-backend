const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

const users = {}; // This should be replaced with a proper database

app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  users[username] = hashedPassword;
  res.status(201).send('User created');
});

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = users[username];

  if (!hashedPassword || !(await bcrypt.compare(password, hashedPassword))) {
    return res.status(401).send('Invalid credentials');
  }

  const token = jwt.sign({ username }, 'secret-key', { expiresIn: '24h' }); // Replace 'secret-key' with a proper secret
  res.status(200).json({ token });
});

app.get('/protected', verifyToken, (req, res) => {
    res.status(200).send(`Welcome ${req.user.username}!`);
});
  