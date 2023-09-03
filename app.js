const express = require('express');
const bodyParser = require('body-parser');
const Users = require('./models/users');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
mongoose.connect('mongodb://localhost/node-auth');
const app = express();

/* Configure body-parser middleware */
app.use(bodyParser.json({ limit: '50mb' }));


/* create user */
app.post('/signup', async (req, res) => {

    try {

        /* Note this is Basic Simple Registration api can't be used directly in real time Projects */

        const { name, email, password } = req.body /* destructuring the field from req.body */

        const salt = await bcrypt.genSalt(10);
        const hashPassword = await bcrypt.hash(password.trim(), salt);  /* encrypt password */

        const user = new Users({
            email: email,
            name: name,
            password: hashPassword,
        });

        const result = await Users.create(user) /* storing user details in database with help of mongoose */

        if (result) return res.status(200).send({ success: true, message: 'Created successfully', data: result })
        else return res.status(400).send({ success: false, message: 'Failed', })
    } catch (error) {
        console.log("error", error);
        return res.status(500).send({ success: false, message: 'Something went wrong', })

    }
});

/* login api */
app.post('/login', async (req, res) => {
    try {

        const { email, password } = req.body

        /* find user based on email */
        const user = await Users.findOne({ email: email });

        /* if no user found with provided email id return error response */
        if (!user) {
            return res.status(401).send({ status: 401, success: false, message: 'Unauthorized' });
        }

        /* generate jwt token with user id payload  the token will be expired in one hour*/
        const token = jwt.sign({ user: user._id }, 'secret-key', { expiresIn: '1h', });

        return res.status(200).send({ success: true, message: 'Logged in successfully', data: token })

    } catch (error) {
        return res.status(500).send({ success: false, message: 'Something went wrong', })
    }

})

/* verify token middleware */
const verifyToken = (req, res, next) => {
    try {

        const { authorization } = req.headers;

        // Check if the Authorization header exists

        if (!authorization) {
            return res.status(401).send({ status: 401, success: false, message: 'Please add token in header' });
        }

        const token = authorization.replace('Bearer ', '');

        /* jwt.verify can compare the toekn with secret and if all good it will return the payload */
        jwt.verify(token, 'secret-key', async (err, payload) => {
            if (err) {
                return res.status(401).json({ status: 401, success: false, message: 'You must be logged in ' });
            }
            const { user } = payload;
            const getUserInfo = await Users.findById(user);
            if (getUserInfo) {
                req.user = getUserInfo;
                next();
            } else {
                return res.status(401).json({ status: 401, success: false, message: 'Un authorized' });
            }
        });

    } catch (error) {
        return res.status(500).send({ success: false, message: 'Something went wrong', })
    }
};


/* Protected Route */
app.get('/users', verifyToken, (req, res) => {
    try {

        /* sample response if you are authorized user you will get this response */
        res.status(200).send({ success: true, message: 'Reponse from Protected endpoint', })

    } catch (error) {
        return res.status(500).send({ success: false, message: 'Something went wrong', })
    }

})

app.post('/refresh', (req, res) => {
    try {

        const { refreshToken } = req.body

        /* verify the refresh token */
        const payload = jwt.verify(refreshToken, 'secret-key');


        // Generate a new JWT
        const token = jwt.sign({ user: payload.user }, 'secret-key', {

            expiresIn: '1h',

        });

        // Return the new JWT as a response

        return res.status(200).send({ success: true, message: 'Refresh token', data: token })

    } catch (error) {
        console.log(error);
        return res.status(500).send({ success: false, message: 'Something went wrong', })
    }
})





/* Start the server with port 3000 */
app.listen(3000, () => console.log('Example app is listening on port 3000.'));
