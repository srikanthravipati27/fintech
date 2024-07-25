const express = require('express');
const axios = require('axios');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
const HASURA_URL = 'https://steady-mole-21.hasura.app/v1/graphql'; 
const JWT_SECRET = 'jfljds'; 


const authenticate = (req, res, next) => {
    const token = req.headers['authorization'];
    if (!token) return res.status(401).json({ error: 'Unauthorized' });

    jwt.verify(token, JWT_SECRET, (err, decoded) => {
        if (err) return res.status(401).json({ error: 'Unauthorized' });
        req.user = decoded;
        next();
    });
};


app.post('/register', async (req, res) => {
    const { name, email, password } = req.body;
    const hashedPassword = await bcrypt.hash(password, 10);
    const mutation = `
        mutation CreateUser($name: String!, $email: String!, $password: String!) {
            insert_users_one(object: {name: $name, email: $email, password: $password}) {
                id
                name
            }
        }
    `;
    try {
        const response = await axios.post(HASURA_URL, {
            query: mutation,
            variables: { name, email, password: hashedPassword }
        });
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


app.post('/login', async (req, res) => {
    const { email, password } = req.body;
    const query = `
        query GetUserByEmail($email: String!) {
            users(where: {email: {_eq: $email}}) {
                id
                name
                password
            }
        }
    `;
    try {
        const response = await axios.post(HASURA_URL, {
            query: query,
            variables: { email }
        });
        const user = response.data.data.users[0];
        if (!user || !await bcrypt.compare(password, user.password)) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }
        const token = jwt.sign({ id: user.id, name: user.name }, JWT_SECRET, { expiresIn: '1h' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


app.post('/deposit', authenticate, async (req, res) => {
    const { amount } = req.body;
    const mutation = `
        mutation Deposit($userId: Int!, $amount: numeric!) {
            insert_transactions_one(object: {user_id: $userId, type: "deposit", amount: $amount}) {
                id
            }
        }
    `;
    try {
        const response = await axios.post(HASURA_URL, {
            query: mutation,
            variables: { userId: req.user.id, amount }
        });
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});


app.post('/withdraw', authenticate, async (req, res) => {
    const { amount } = req.body;
    const mutation = `
        mutation Withdraw($userId: Int!, $amount: numeric!) {
            insert_transactions_one(object: {user_id: $userId, type: "withdraw", amount: $amount}) {
                id
            }
        }
    `;
    try {
        const response = await axios.post(HASURA_URL, {
            query: mutation,
            variables: { userId: req.user.id, amount }
        });
        res.json(response.data);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(3000, () => {
    console.log('Server running on port 3000');
});
