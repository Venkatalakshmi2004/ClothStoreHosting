const path = require('path');
const express = require('express');
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcrypt');

const { createUser, findUserByEmail, getUserById } = require('./db');

const app = express();
const port = process.env.PORT || 3000;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'views'));

app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '..', 'public')));

app.use(
    session({
        store: new SQLiteStore({
            db: 'sessions.sqlite',
            dir: path.join(__dirname, '..', 'data'),
        }),
        secret: process.env.SESSION_SECRET || 'dev_secret_change_me',
        resave: false,
        saveUninitialized: false,
        cookie: {
            maxAge: 1000 * 60 * 60 * 24 * 7, // 7 days
        },
    })
);

// Flash helper (one-time messages)
app.use((req, res, next) => {
    res.locals.currentUserId = req.session.userId || null;
    res.locals.flash = req.session.flash || null;
    delete req.session.flash;
    next();
});

function requireAuth(req, res, next) {
    if (!req.session.userId) {
        req.session.flash = { type: 'error', message: 'Please sign in first.' };
        return res.redirect('/signin');
    }
    next();
}

app.get('/', async (req, res) => {
    let user = null;
    if (req.session.userId) {
        user = await getUserById(req.session.userId).catch(() => null);
    }
    res.render('index', { user });
});

app.get('/signup', (req, res) => {
    res.render('signup', { values: { email: '' }, error: null });
});

app.post('/signup', async (req, res) => {
    const { email, password, confirmPassword } = req.body;
    const trimmedEmail = String(email || '').trim().toLowerCase();

    if (!trimmedEmail || !password || !confirmPassword) {
        return res.status(400).render('signup', {
            values: { email: trimmedEmail },
            error: 'All fields are required.',
        });
    }

    if (password !== confirmPassword) {
        return res.status(400).render('signup', {
            values: { email: trimmedEmail },
            error: 'Passwords do not match.',
        });
    }

    try {
        const existing = await findUserByEmail(trimmedEmail);
        if (existing) {
            return res.status(400).render('signup', {
                values: { email: trimmedEmail },
                error: 'Email is already registered.',
            });
        }

        const passwordHash = await bcrypt.hash(password, 12);
        await createUser(trimmedEmail, passwordHash);

        const created = await findUserByEmail(trimmedEmail);
        req.session.userId = created.id;
        req.session.flash = { type: 'success', message: 'Welcome!' };
        res.redirect('/dashboard');
    } catch (error) {
        console.error('Signup error:', error);
        res.status(500).render('signup', {
            values: { email: trimmedEmail },
            error: 'Something went wrong. Please try again.',
        });
    }
});

app.get('/signin', (req, res) => {
    res.render('signin', { values: { email: '' }, error: null });
});

app.post('/signin', async (req, res) => {
    const { email, password } = req.body;
    const trimmedEmail = String(email || '').trim().toLowerCase();

    if (!trimmedEmail || !password) {
        return res.status(400).render('signin', {
            values: { email: trimmedEmail },
            error: 'Email and password are required.',
        });
    }

    try {
        const user = await findUserByEmail(trimmedEmail);
        if (!user) {
            return res.status(400).render('signin', {
                values: { email: trimmedEmail },
                error: 'Invalid email or password.',
            });
        }

        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            return res.status(400).render('signin', {
                values: { email: trimmedEmail },
                error: 'Invalid email or password.',
            });
        }

        req.session.userId = user.id;
        req.session.flash = { type: 'success', message: 'Signed in successfully.' };
        res.redirect('/dashboard');
    } catch (error) {
        console.error('Signin error:', error);
        res.status(500).render('signin', {
            values: { email: trimmedEmail },
            error: 'Something went wrong. Please try again.',
        });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy(() => {
        res.redirect('/');
    });
});

app.get('/dashboard', requireAuth, async (req, res) => {
    const user = await getUserById(req.session.userId);
    res.render('dashboard', { user });
});

app.use((req, res) => {
    res.status(404).send('Not Found');
});

app.listen(port, () => {
    console.log(`Server running on http://localhost:${port}`);
});

