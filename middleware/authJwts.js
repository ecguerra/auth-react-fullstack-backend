const jwt = require('jsonwebtoken')
const config = require('../config/auth.config')
const db = require('../models/index')

const User = db.user
const Role = db.role

verifyWebToken = (req, res, next) => {
    // declare token which is passed in our headers
    let token = req.headers['x-access-token']

    // if there's no token, respond with error
    if(!token) {
        return res.status(403).send({message: 'No token provided!'})
    }

    // try to verify the token
    jwt.verify(token, config.secret, (err, decoded) => {
        if(err) {
            return res.status(401).send({message: 'Unauthorized'})
        }
        // set userId to decoded id
        req.userId = decoded.userId
        next()
    })
}

// Function to verify is user is admin or not

isAdmin = (req,res,next) => {
    // .exec returns the user we want access to // .then will not
    User.find({_id: req.userId}).exec((err, user)=>{
        // throw error because user doesn't exist
        if(err) {
            return res.status(500).send({message:err})
        }
        // find the user's role, if the user exists
        Role.find({
            _id: {$in: user.roles}
        }, (err, roles)=> {
            if(err) {
                return res.status(500).send({message: err})
            }
            
            // loop through user's roles and check if there's an admin role
            for(let i = 0; i < roles.length; i++) {
                if(roles[i].name === 'admin') {
                    next()
                    return
                }
            }

            // if user doesn't have an admin role, send a status 403 message (IT'S FORBIDDEN)
            res.status(403).send({message: 'Requires admin role'})
        })
    })
}

// add those to an object
const authJwt = {
    verifyWebToken,
    isAdmin
}

module.exports = authJwt