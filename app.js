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
    secret: 'test1234',
    resave: false,
    saveUninitialized: false
}));
app.use(express.static('./public'));

/*
 * TODO: well-known を利用する
 */
const authEndpoint = 'https://example.com/authorize';
const clientId = process.env.CLIENT_ID || 'your client id';
const clientSecret = process.env.CLIENT_SECRET || 'your client secret';
const redirectUri = 'http://localhost:3000/callback';
const tokenEndpoint = 'https://example.com/token';

app.get('/auth', (req, res) => {
    // Authentication Request
    const responseType = 'code';
    const scope = 'openid profile';

    const state = randomstring.generate();
    req.session.state = state;

    const nonce = randomstring.generate();
    req.session.nonce = nonce;

    res.redirect(`${authEndpoint}?response_type=${responseType}&client_id=${clientId}&redirect_uri=${redirectUri}&scope=${scope}&state=${state}&nonce=${nonce}`);
});

// ここをasyncにするとcatchが漏れる
app.get('/callback', async (req, res) => {
    // stateチェック
    if (req.query.state != req.session.state) {
        return res.status(500).send({ error: 'State value did not match.' });
    }

    // エラーチェック
    if (req.query.error) {
        return res.status(500).send({
            error: req.query.error,
            description: req.query.error_description,
            uri: req.query.error_uri
        });
    }

    // Token Request
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
    }).then(res => res.json());

console.log(token);

    // TODO トークンリクエストのエラーを拾う


    // TODO ID Token Validation
    const idtokenString = Buffer.from(token.id_token.split('.')[1], 'base64').toString();
    const idtoken = JSON.parse(idtokenString);
    /* TODO */
    // issチェック
    // audチェック
    // expチェック
    // iatチェック
    // maxageチェック
    // nonceチェック

    res.render('attr.ejs', { idtoken });
});

app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`);
});
