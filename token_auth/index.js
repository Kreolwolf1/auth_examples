const express = require('express');
const onFinished = require('on-finished');
const bodyParser = require('body-parser');
const path = require('path');
const port = 3000;
const auth0 = require('auth0')
const jwt = require('jsonwebtoken')
const emailValidator = require('email-validator');
const {auth, requiredScopes} = require('express-oauth2-jwt-bearer');

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({extended: true}));

const AUTHORIZATION_KEY = 'Authorization';

const AuthenticationClient = new auth0.AuthenticationClient(
    {
        domain: 'dev-pa5jh1kbknfmplvz.us.auth0.com',
        clientId: 'IBD5KfpnSaNOqfhYiyqbtnw2uwrKehsP',
        clientSecret: 'K6iFygMuS8FndiKPtsp0CVv3GE8qIfx9XKgD_madeSMNuAuk9zwIvjTXrO20NGHk'
    }
);

const ManagementClient = new auth0.ManagementClient(
    {
        domain: 'dev-pa5jh1kbknfmplvz.us.auth0.com',
        clientId: 'IBD5KfpnSaNOqfhYiyqbtnw2uwrKehsP',
        clientSecret: 'K6iFygMuS8FndiKPtsp0CVv3GE8qIfx9XKgD_madeSMNuAuk9zwIvjTXrO20NGHk'
    }
)

app.use(async (req, res, next) => {
    let authorization = req.get(AUTHORIZATION_KEY);
    let refresh = req.get('Refresh');

    if (authorization) {
        req.access_token = authorization.split(' ')[1];
        req.refresh_token = refresh;
        try {
            let payload = jwt.decode(req.access_token);
            console.log(payload)

            if (Date.now() >= payload.exp * 1000) {
                console.log('expired', payload.exp);

                let refreshRequest = await AuthenticationClient.refreshToken(
                    {
                        refresh_token: req.refresh_token
                    }
                );

                req.access_token = refreshRequest.access_token;

                console.log("refreshed", refreshRequest);
            }
        } catch (err) {
            console.log(err)
            res.status(401).send();
            return;
        }

        res.headers = {Authorization: `${req.access_token};${req.refresh_token}`}
    }

    next();
});

app.get('/', (req, res) => {
    if (req.access_token) {
        let payload = jwt.decode(req.access_token);

        return res.json({
            username: payload.sub,
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
        console.log(err);
        return;
    }
    console.log(loginResult);

    res.json({
        access_token: loginResult.access_token,
        refresh_token: loginResult.refresh_token
    });
});

const checkJwt = auth({
    audience: 'https://dev-pa5jh1kbknfmplvz.us.auth0.com/api/v2/',
    issuerBaseURL: `https://dev-pa5jh1kbknfmplvz.us.auth0.com`,
});

app.get('/api/private', checkJwt, (req, res) => {
    res.json({
        message: 'You are authenticated'
    })
})


app.post('/api/register', async (req, res) => {
    const {email, password} = req.body;
    let createResult = {}

    try {
        createResult = await ManagementClient.createUser(
            {
                email: email,
                password: password,
                connection: 'Username-Password-Authentication'
            }
        );

        if (createResult instanceof Error) {
            throw createResult;
        }
    } catch (err) {
        res.status(400).send();
        console.log(err);

        return;
    }

    console.log(createResult)
    res.status(200).send();
});

async function auth0Login(login, password) {
    const data = {
        audience: 'https://dev-pa5jh1kbknfmplvz.us.auth0.com/api/v2/',
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
