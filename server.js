// server.js
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
const PORT = 3000;
const SECRET_KEY = 'your-very-secure-secret'; // In production, use environment variables!

// Enable CORS for frontend (e.g., Live Server on port 5500)
app.use(cors({
    origin: ['http://127.0.0.1:5500', 'http://localhost:5500'] // Adjust based on your frontend URL
}));

// Middleware to parse JSON
app.use(express.json());

// In-memory "database" (replace with MongoDB later)
let users = [
    { 
        id: 1, 
        email: 'nerisergio@adminmail.com', // Changed from username
        password: bcrypt.hashSync('Password123!', 10), 
        role: 'admin',
        fname: 'Sergio',
        lname: 'Neri'
    },
    { 
        id: 2, 
        email: 'student@example.com', 
        password: bcrypt.hashSync('user123', 10), 
        role: 'user',
        fname: 'Juan',
        lname: 'Dela Cruz'
    }
];

//AUTH ROUTES

// POST /api/register
app.post('/api/register', async (req, res) => {
    const { email, password, role = 'user', fname, lname } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email and password required' });
    }

    const existing = users.find(u => u.email === email);
    if (existing) {
        return res.status(409).json({ error: 'User already exists' });
    }

    const hashedPassword = await bcrypt.hash(password, 10);
    const newUser = {
        id: users.length + 1,
        email,
        password: hashedPassword,
        role,
        fname,
        lname
    };

    users.push(newUser);
    res.status(201).json({ message: 'User registered', email, role });
});

// POST /api/login
app.post('/api/login', async (req, res) => {
    const { email, password } = req.body; // Changed from username to email

    const user = users.find(u => u.email === email);
    if (!user || !await bcrypt.compare(password, user.password)) {
        return res.status(401).json({ error: 'Invalid credentials' });
    }

    const payload = { 
        id: user.id, 
        fname: user.fname, 
        lname: user.lname, 
        email: user.email, 
        role: user.role 
    };

    const token = jwt.sign(
        payload,
        SECRET_KEY,
        { expiresIn: '1h' }
    );

    res.json({ 
        token, 
        user: { 
            id: user.id,
            fname: user.fname, 
            lname: user.lname,
            email: user.email, 
            role: user.role 
        } 
    });
});

//PROTECTED ROUTE: Get user profile
app.get('/api/profile', authenticateToken, (req, res) => {
    res.json({ user: req.user });
});

//ROLE-BASED PROTECTED ROUTE: Admin-only
app.get('/api/admin/dashboard', authenticateToken, authorizeRole('admin'), (req, res) => {
    res.json({ message: 'Welcome to admin dashboard!', data: 'Secret admin info' });
});

//PUBLIC ROUTE: Guest content
app.get('/api/content/guest', (req, res) => {
    res.json({ message: 'Public content for all visitors' });
});

let serverDatabase = { 
    accounts: [], 
    departments: [], 
    employees: [], 
    requests: [] 
};

app.get('/api/database', authenticateToken, (req, res) => {
    res.json(serverDatabase);
});

app.post('/api/database/update', authenticateToken, (req, res) => {
    serverDatabase = req.body; 
    res.json({ success: true, message: "Data saved on server!" });
});

//MIDDLEWARE

// Token authentication
function authenticateToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) return res.status(401).json({ error: 'Access token required' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ error: 'Invalid or expired token' });
        req.user = user; // This now contains { email, role, id }
        next();
    });
}

// Role authorization
function authorizeRole(role) {
    return (req, res, next) => {
        if (req.user.role !== role) {
            return res.status(403).json({ error: 'Access denied: insufficient permissions' });
        }
        next();
    };
}

// Start server
app.listen(PORT, () => {
    console.log(`Backend running on http://localhost:${PORT}`);
    console.log(`Try logging in with:`);
    console.log(`  - Admin: email=nerisergio@adminmail.com, password=Password123!`);
    console.log(`  - User: email=student@example.com, password=user123`);
});