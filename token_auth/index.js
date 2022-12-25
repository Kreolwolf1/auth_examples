const express = require('express');
const onFinished = require('on-finished');
const bodyParser = require('body-parser');
const path = require('path');
const port = 3000;
const auth0 = require('auth0')
const Session = require('./session.js')
const jwt = require('jsonwebtoken')
const {json} = require("express");

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

const SESSION_KEY = 'Authorization';

const sessions = new Session();
const AuthenticationClient = new auth0.AuthenticationClient(
    {
        domain: 'dev-pa5jh1kbknfmplvz.us.auth0.com',
        clientId: 'IBD5KfpnSaNOqfhYiyqbtnw2uwrKehsP',
        clientSecret: 'K6iFygMuS8FndiKPtsp0CVv3GE8qIfx9XKgD_madeSMNuAuk9zwIvjTXrO20NGHk'
    }
);

app.use(async (req, res, next) => {
    let authorization = req.get(SESSION_KEY);

    if (authorization) {
        let tokens = authorization.split(';');
        if (tokens.length === 3) {
            req.access_token = tokens[0];
            req.refresh_token = tokens[1];
            req.id_token = tokens[2];
        }
        try {
            let payload = jwt.decode(req.id_token);

            if (Date.now() >= payload.exp * 1000) {
                console.log('expired', payload.exp);

                let refreshRequest = await AuthenticationClient.refreshToken(
                        {
                            refresh_token: req.refresh_token
                        }
                );

                req.access_token = refreshRequest.access_token;
                req.id_token = refreshRequest.id_token;

                console.log("refreshed", refreshRequest);
            }
        } catch (err) {
            res.status(401).send();
            return;
        }

        res.headers = {Authorization: `${req.access_token};${req.refresh_token};${req.id_token}`}
    }

    next();
})
;

app.get('/', (req, res) => {
    if (req.access_token) {
        let payload = jwt.decode(req.id_token);

        return res.json({
            username: payload.nickname,
            logout: 'http://localhost:3000/logout'
        })
    }
    res.sendFile(path.join(__dirname + '/index.html'));
})

app.get('/logout', (req, res) => {
    sessionStorage.clear()

    res.redirect('/');
});

app.post('/api/login', async (req, res) => {
    const {login, password} = req.body;

    let loginResult = {};

    try {
        loginResult = await auth0Login(login, password);
    } catch (err) {
        res.status(401).send();

        return;
    }
    console.log(loginResult);

    res.json({access_token: loginResult.access_token, refresh_token: loginResult.refresh_token, id_token: loginResult.id_token});
});

async function auth0Login(login, password) {
    const data = {
        client_id: 'IBD5KfpnSaNOqfhYiyqbtnw2uwrKehsP',
        username: login,
        password: password,
        realm: 'Username-Password-Authentication',
        scope: 'offline_access'
    };

    return AuthenticationClient.passwordGrant(data);
}

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
