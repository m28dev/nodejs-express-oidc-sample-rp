const express = require('express');
const app = express();
const port = 3000;

const path = require('path');
const session = require('express-session');
const fetch = require('node-fetch');
const randomstring = require("randomstring");

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(session({
    secret: process.env.SESSION_SECRET || 'test1234',
    resave: false,
    saveUninitialized: false
}));

app.use(express.static('./public'));

// OIDC Settings
const issuer = process.env.ISSUER || 'http://localhost:8180';
const clientId = process.env.CLIENT_ID || 'Input your ClientID';
const clientSecret = process.env.CLIENT_SECRET || 'Input your secret';
const redirectUri = 'http://localhost:3000/callback';

let metadata = {};

// routes
app.get('/auth', [
    (req, res, next) => {
        // OPの情報を取得
        fetch(`${issuer}/.well-known/openid-configuration`).then(response => {
            return response.json();
        }).then(json => {
            metadata = json;
            next();
        }).catch(err => {
            next(err);
        });
    },
    (req, res) => {
        const authEndpoint = metadata.authorization_endpoint;

        // Authentication Request
        const scope = 'openid profile';
        const responseType = 'code';

        const state = randomstring.generate();
        req.session.state = state;

        const nonce = randomstring.generate();
        req.session.nonce = nonce;

        res.redirect(authEndpoint +
            '?response_type=' + responseType +
            '&scope=' + scope +
            '&client_id=' + clientId +
            '&state=' + state +
            '&redirect_uri=' + redirectUri +
            '&nonce=' + nonce
        );
    }
]);

app.get('/callback', async (req, res, next) => {
    const state = req.session.state;
    const nonce = req.session.nonce;
    req.session.state = null;
    req.session.nonce = null;

    try {
        // Check State
        if (!state || req.query.state !== state) {
            throw new Error('State value did not match.');
        }

        // Check Authentication Error Response
        if (req.query.error) {
            console.error('Authentication Error:', {
                error: req.query.error,
                description: req.query.error_description,
                uri: req.query.error_uri
            });
            throw new Error('Authentication Error');
        }

        // Token Request
        const tokenEndpoint = metadata.token_endpoint;
        const params = new URLSearchParams();
        params.append('grant_type', 'authorization_code');
        params.append('code', req.query.code);
        params.append('redirect_uri', redirectUri);

        const token = await fetch(tokenEndpoint, {
            method: 'POST',
            headers: {
                'Authorization': `Basic ${Buffer.from(`${clientId}:${clientSecret}`).toString('base64')}`
            },
            body: params
        }).then(async response => {
            if (!response.ok) {
                await response.json().then(errObj => { console.error('Token Request Error:', errObj) });
                throw new Error('Token Request Error');
            } else {
                return response.json();
            }
        });

        // TODO: ID Token Validation
        const idtokenString = Buffer.from(token.id_token.split('.')[1], 'base64').toString();
        const idtoken = JSON.parse(idtokenString);

        // TODO?
        res.render('attr.ejs', { idtoken });

    } catch (err) {
        next(err);
    }
});

// start server
app.listen(port, () => {
    console.log(`listening at http://localhost:${port}`);
});
