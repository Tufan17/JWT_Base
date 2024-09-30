const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');

const app = express();
const port = 3000;

app.use(bodyParser.json());

const users = [];  // Veritabanı yerine basit bir dizi kullanacağız

// JWT Secret Key
const JWT_SECRET = 'your_jwt_secret_key';

// Kullanıcı Kaydı
app.get('/', (req, res) => {
  res.json({ message: 'Welcome to the API!' });
});

app.post('/register', async (req, res) => {
  const { username, password } = req.body;

  // Şifreyi hashle
  const hashedPassword = await bcrypt.hash(password, 10);

  // Kullanıcıyı ekle
  users.push({ username, password: hashedPassword });
  res.status(201).json({ message: 'User registered successfully' });
});

// Kullanıcı Girişi
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // Kullanıcıyı bul
  const user = users.find(user => user.username === username);
  if (!user) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  // Şifreyi doğrula
  const isValidPassword = await bcrypt.compare(password, user.password);
  if (!isValidPassword) {
    return res.status(400).json({ error: 'Invalid credentials' });
  }

  // JWT oluştur
  const token = jwt.sign({ username: user.username }, JWT_SECRET, { expiresIn: '1h' });

  res.json({ message: 'Login successful', token });
});

// Korunan rota
app.get('/protected', (req, res) => {
  const token = req.headers['authorization'];

  if (!token) {
    return res.status(401).json({ error: 'Access denied. No token provided.' });
  }

  try {
    const decoded = jwt.verify(token.split(' ')[1], JWT_SECRET);
    res.json({ message: 'Protected data', user: decoded });
  } catch (error) {
    res.status(401).json({ error: 'Invalid token' });
  }
});

app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`);
});
