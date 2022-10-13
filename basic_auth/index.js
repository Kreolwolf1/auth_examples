const express = require('express')
const app = express()
const port = 3000

app.use((req, res, next) => {
    console.log('\n=======================================================\n');

    const authorizationHeader = req.get('Authorization');
    console.log('authorizationHeader', authorizationHeader);

    if (!authorizationHeader) {
        res.setHeader('WWW-Authenticate', 'Basic realm="Ukraine"');
        res.status(401);
        res.send('Unauthorized');
        return;
    }

    const authorizationBase64Part = authorizationHeader.split(' ')[1];

    const decodedAuthorizationHeader = Buffer.from(authorizationBase64Part, 'base64').toString('utf-8');
    console.log('decodedAuthorizationHeader', decodedAuthorizationHeader);

    const login = decodedAuthorizationHeader.split(':')[0];
    const password = decodedAuthorizationHeader.split(':')[1];
    console.log('Login/Password', login, password);

    if (login == 'DateArt' && password == '2408') {
        req.login = login;
        return next();
    }

    res.setHeader('WWW-Authenticate', 'Basic realm="Ukraine"');
    res.status(401);
    res.send('Unauthorized');
});

app.get('/', (req, res) => {
    res.send(`Hello ${req.login}`);
})

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`)
})
