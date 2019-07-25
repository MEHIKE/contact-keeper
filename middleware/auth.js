const jwt = require('jsonwebtoken')
const config = require('config')

module.exports = function(req, res, next) {
    //Get the token from header
    const token = req.header('x-auth-token');

    //check if not token
    if (!token) {
        return res.status(401).json({ msg: 'No token, authorization denied'});
    }
    //console.log(`${token}`)
    try {
        const decodes = jwt.verify(token, config.get('jwtSecret'));
        //console.log(`${decodes}`)
        req.user = decodes.user;
        //console.log(`${req.user.name}`)
        next();
    } catch (err) {
        res.status(401).json({ msg: 'Token is not valid'})
    }
}