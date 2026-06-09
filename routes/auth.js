const express = require('express');
const router = express.Router();
const User = require('../models/User');
const validator = require('validator');
const jwt = require('jsonwebtoken');
const csrf = require('csurf');
const logger = require('../logger');

const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const MAX_LOGIN_ATTEMPTS = 5;
const csrfProtection = csrf();

function escapeHtml(value = '') {
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function renderPage(title, body) {
    return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${escapeHtml(title)}</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 0; background: #f5f7fb; color: #1f2937; }
        .wrap { max-width: 720px; margin: 40px auto; padding: 24px; }
        .card { background: #fff; border-radius: 12px; padding: 24px; box-shadow: 0 10px 30px rgba(0,0,0,0.08); }
        h1 { margin-top: 0; }
        label { display: block; margin-top: 14px; font-weight: 600; }
        input { width: 100%; padding: 10px 12px; margin-top: 6px; border: 1px solid #cbd5e1; border-radius: 8px; box-sizing: border-box; }
        button, .link-btn { display: inline-block; margin-top: 16px; padding: 10px 14px; border: 0; border-radius: 8px; background: #2563eb; color: #fff; text-decoration: none; cursor: pointer; }
        .muted { color: #6b7280; }
        .error { color: #b91c1c; margin-top: 12px; }
        .row { margin-top: 12px; }
        code { background: #eef2ff; padding: 2px 6px; border-radius: 6px; }
    </style>
</head>
<body>
    <div class="wrap">
        <div class="card">
            ${body}
        </div>
    </div>
</body>
</html>`;
}

function csrfField(token) {
    return `<input type="hidden" name="_csrf" value="${escapeHtml(token)}">`;
}

function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.redirect('/login');
    }

    next();
}

router.use(csrfProtection);

router.get('/', (req, res) => {
    if (req.session.userId) {
        return res.redirect('/profile');
    }

    res.redirect('/signup');
});

router.get('/signup', (req, res) => {
    res.send(renderPage('Sign Up', `
        <h1>Create account</h1>
        <p class="muted">Register a new user with email and password.</p>
        <form method="POST" action="/signup">
            ${csrfField(req.csrfToken())}
            <label for="email">Email</label>
            <input id="email" name="email" type="email" required>

            <label for="password">Password</label>
            <input id="password" name="password" type="password" required>

            <button type="submit">Sign up</button>
        </form>
        <p class="row">Already have an account? <a href="/login">Log in</a></p>
    `));
});

router.post('/signup', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate inputs
        if (!email || !password) {
            logger.warn(`Signup attempt with missing fields from IP: ${req.ip}`);
            return res.status(400).send(renderPage('Sign Up', '<h1>Create account</h1><p class="error">Email and password are required.</p><p><a href="/signup">Go back</a></p>'));
        }

        // Validate email format
        if (!validator.isEmail(email)) {
            logger.warn(`Signup attempt with invalid email format: ${email} from IP: ${req.ip}`);
            return res.status(400).send(renderPage('Sign Up', '<h1>Create account</h1><p class="error">Invalid email format.</p><p><a href="/signup">Go back</a></p>'));
        }

        // Validate password strength
        if (password.length < 6) {
            logger.warn(`Signup attempt with weak password from email: ${email}`);
            return res.status(400).send(renderPage('Sign Up', '<h1>Create account</h1><p class="error">Password must be at least 6 characters long.</p><p><a href="/signup">Go back</a></p>'));
        }

        const existingUser = await User.findOne({ email });

        if (existingUser) {
            logger.warn(`Signup attempt with existing email: ${email}`);
            return res.status(409).send(renderPage('Sign Up', '<h1>Create account</h1><p class="error">An account with that email already exists.</p><p><a href="/signup">Try again</a></p>'));
        }

        const user = new User({ email, password });
        await user.save();

        // Generate JWT token
        const token = jwt.sign({ id: user._id }, JWT_SECRET);

        req.session.userId = user._id.toString();
        req.session.token = token;
        
        logger.info(`New user registered: ${email}`);
        res.redirect('/profile');
    } catch (error) {
        logger.error(`Signup error: ${error.message}`);
        res.status(500).send(renderPage('Sign Up', `<h1>Create account</h1><p class="error">${escapeHtml(error.message)}</p><p><a href="/signup">Try again</a></p>`));
    }
});


router.get('/login', (req, res) => {
    res.send(renderPage('Log In', `
        <h1>Log in</h1>
        <p class="muted">Use your registered email and password.</p>
        <form method="POST" action="/login">
            ${csrfField(req.csrfToken())}
            <label for="email">Email</label>
            <input id="email" name="email" type="email" required>

            <label for="password">Password</label>
            <input id="password" name="password" type="password" required>

            <button type="submit">Log in</button>
        </form>
        <p class="row">Need an account? <a href="/signup">Sign up</a></p>
    `));
});

router.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        // Validate inputs
        if (!email || !password) {
            logger.warn(`Login attempt with missing fields from IP: ${req.ip}`);
            return res.status(400).send(renderPage('Log In', '<h1>Log in</h1><p class="error">Email and password are required.</p><p><a href="/login">Try again</a></p>'));
        }

        // Validate email format
        if (!validator.isEmail(email)) {
            logger.warn(`Login attempt with invalid email format: ${email} from IP: ${req.ip}`);
            return res.status(400).send(renderPage('Log In', '<h1>Log in</h1><p class="error">Invalid email format.</p><p><a href="/login">Try again</a></p>'));
        }

        const user = await User.findOne({ email });

        if (user && user.isLoginLocked()) {
            logger.warn(`Locked account login attempt for email: ${email} from IP: ${req.ip}`);
            return res.status(423).send(renderPage('Log In', '<h1>Log in</h1><p class="error">This account is temporarily locked due to too many failed login attempts. Try again later.</p><p><a href="/login">Try again</a></p>'));
        }

        if (!user || !(await user.comparePassword(password))) {
            if (user) {
                user.registerFailedLogin(LOGIN_WINDOW_MS, MAX_LOGIN_ATTEMPTS);
                await user.save();

                if (user.isLoginLocked()) {
                    logger.warn(`Account locked after repeated failed login attempts for email: ${email} from IP: ${req.ip}`);
                    return res.status(423).send(renderPage('Log In', '<h1>Log in</h1><p class="error">Too many failed attempts. This account has been temporarily locked.</p><p><a href="/login">Try again later</a></p>'));
                }
            }

            logger.warn(`Failed login attempt for email: ${email} from IP: ${req.ip}`);
            return res.status(401).send(renderPage('Log In', '<h1>Log in</h1><p class="error">Invalid email or password.</p><p><a href="/login">Try again</a></p>'));
        }

        user.clearLoginFailures();
        await user.save();

        // Generate JWT token
        const token = jwt.sign({ id: user._id }, JWT_SECRET);

        req.session.userId = user._id.toString();
        req.session.token = token;
        
        logger.info(`User logged in: ${email} from IP: ${req.ip}`);
        res.redirect('/profile');
    } catch (error) {
        logger.error(`Login error: ${error.message}`);
        res.status(500).send(renderPage('Log In', `<h1>Log in</h1><p class="error">${escapeHtml(error.message)}</p><p><a href="/login">Try again</a></p>`));
    }
});


router.get('/profile', requireAuth, async (req, res) => {
    try {
        const user = await User.findById(req.session.userId);

        if (!user) {
            req.session.destroy(() => {
                res.redirect('/login');
            });
            return;
        }

        res.send(renderPage('Profile', `
            <h1>User profile</h1>
            <p class="muted">View and update the current account.</p>
            <p><strong>Email:</strong> <code>${escapeHtml(user.email)}</code></p>
            <form method="POST" action="/profile">
                ${csrfField(req.csrfToken())}
                <label for="email">Email</label>
                <input id="email" name="email" type="email" value="${escapeHtml(user.email)}" required>

                <label for="password">New Password (leave blank to keep current)</label>
                <input id="password" name="password" type="password">

                <button type="submit">Update profile</button>
            </form>
            <form method="POST" action="/logout">
                ${csrfField(req.csrfToken())}
                <button type="submit" style="background:#475569;">Log out</button>
            </form>
        `));
    } catch (error) {
        res.status(500).send(renderPage('Profile', `<h1>User profile</h1><p class="error">${escapeHtml(error.message)}</p>`));
    }
});

router.post('/profile', requireAuth, async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findById(req.session.userId);

        if (!user) {
            return res.redirect('/login');
        }

        // Validate email format
        if (email && !validator.isEmail(email)) {
            logger.warn(`Profile update with invalid email format: ${email} by user: ${user.email}`);
            return res.status(400).send(renderPage('Profile', '<h1>User profile</h1><p class="error">Invalid email format.</p><p><a href="/profile">Go back</a></p>'));
        }

        // Validate password strength if provided
        if (password && password.length > 0 && password.length < 6) {
            logger.warn(`Profile update with weak password by user: ${user.email}`);
            return res.status(400).send(renderPage('Profile', '<h1>User profile</h1><p class="error">Password must be at least 6 characters long.</p><p><a href="/profile">Go back</a></p>'));
        }

        // Check if email is already in use by another user
        if (email && email !== user.email) {
            const existingUser = await User.findOne({ email });
            if (existingUser) {
                logger.warn(`Profile update attempted with existing email: ${email} by user: ${user.email}`);
                return res.status(409).send(renderPage('Profile', '<h1>User profile</h1><p class="error">This email is already in use.</p><p><a href="/profile">Go back</a></p>'));
            }
            user.email = email;
        }

        // Update password only if provided
        if (password && password.length > 0) {
            user.password = password;
        }

        await user.save();

        logger.info(`User profile updated: ${email || user.email}`);
        res.redirect('/profile');
    } catch (error) {
        logger.error(`Profile update error: ${error.message}`);
        res.status(500).send(renderPage('Profile', `<h1>User profile</h1><p class="error">${escapeHtml(error.message)}</p><p><a href="/profile">Go back</a></p>`));
    }
});

router.post('/logout', (req, res) => {
    const userId = req.session.userId;
    logger.info(`User logged out: ${userId}`);
    req.session.destroy(() => {
        res.redirect('/login');
    });
});

router.use((error, req, res, next) => {
    if (error.code !== 'EBADCSRFTOKEN') {
        return next(error);
    }

    const backLink = req.originalUrl.startsWith('/profile') || req.originalUrl.startsWith('/logout')
        ? '/profile'
        : req.originalUrl.startsWith('/login')
            ? '/login'
            : '/signup';

    logger.warn(`CSRF token validation failed for ${req.method} ${req.originalUrl} from IP: ${req.ip}`);
    return res.status(403).send(renderPage('Security Check Failed', `
        <h1>Security check failed</h1>
        <p class="error">Your form session expired or the request was invalid. Please go back and try again.</p>
        <p class="row"><a href="${backLink}">Go back</a></p>
    `));
});

module.exports = router;