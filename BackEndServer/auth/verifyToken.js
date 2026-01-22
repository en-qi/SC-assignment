require('dotenv').config();  // ← ADD THIS LINE

var jwt = require('jsonwebtoken');

var config = require('../config');

function verifyToken(req, res, next) {
    console.log(req.headers);

    var token = req.headers['authorization']; //retrieve authorization header's content
    console.log(token);

    if (!token || !token.includes('Bearer')) { //process the token
        res.status(403);
        return res.send({ auth: 'false', message: 'Not authorized!' });
    }
    else {
        token = token.split('Bearer ')[1]; //obtain the token's value
        //console.log(token);
        jwt.verify(token, process.env.JWT_SECRET || config.key, function (err, decoded) {
            if (err) {
                res.status(403);
                return res.send({ auth: false, message: 'Not authorized!' });
            }
            else {
                req.userid = decoded.userid; //decode the userid and store in req for use
                req.type = decoded.type; //decode the role and store in req for use
                next();
            }
        });
    }
}

module.exports = verifyToken;