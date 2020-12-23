const config = require('../config/auth.config')
const db = require('../models/index')

const User = db.user
const Role = db.role

// this will give access to encode and decode the jwt itself. (allows us to work with jwt)
const jwt = require('jsonwebtoken')
// for hashing / encrypting passwords
const bcrypt = require('bcryptjs')

// this will handle stand up
exports.signup = (req, res) => {

    // we are going to make our user object using the params returned from req
    const user = new User({
        username: req.body.username,
        email: req.body.email,
        password: bcrypt.hashSync(req.body.password, 8)
    })

    // we save that user, and if there's an error, we return that error
    user.save((err, user) => {
        if(err) {
            res.status(500).send({message: err})
            return
        }

        // if no error, we check if roles was passed on req.params
        if(req.body.roles) {
            Role.find({
                name: {$in: req.body.roles}
            }, (err, roles) => {
                if(err) {
                    res.status(500).send({message: err})
                    return
                }

                // pass roles id from query above to user.roles
                user.roles = roles.map(role => role._id)

                // save our updated user
                user.save(err => {
                    if(err) {
                        res.status(500).send({message: err})
                        return
                    }

                    res.send({message: 'User created successfully!'})
                })
            })

        // every user that doesn't have a role will automatically get a user role
        } else {
            Role.findOne({name: 'user'}, (err,role) => {
                if(err) {
                    res.status(500).send({message: err})
                    return
                }

                // just assign user role id to document
                user.roles = [role._id]

                user.save(err => {
                    if(err) {
                        res.status(500).send({message: err})
                        return
                    }
                    res.send({message: 'user was registered successfully!'})
                })
            })
        }
    })
}

exports.signin = (req, res) => {
    User.findOne({
        username: req.body.username
    })
    // populates values from the roles id we stored in the document
    .populate('roles', '-__v')
    // exec returning our user to user
    .exec((err, user) => {
        if(err) {
            res.status(500).send({message: err})
            return
        }

        // user did not exist
        if(!user) {
            return res.status(404).send({message: '404\'d! User not found'})
        }

        // validates the password by passing req.body password and the passowrd returned from db over to bcrypt to unhash and compare
        const passwordIsValid = bcrypt.compareSync(
            req.body.password, // unencrypted password from req.body
            user.password // encrypted password saved in db
        )

        // if password is not valid, return invalid password // boolean
        if(!passwordIsValid) {
            return res.status(401).send({accessToken: null, message: 'invalid password'})
        }

        // if password is valid we generate a new token
        const token = jwt.sign({id: user._id}, config.secret, {
            expiresIn: 86400 // token expires in 24 hours
        })

        // setting roles to pass back in our response
        let authorities = []

        for(let i=0; i<user.roles.length; i++) {
            authorities.push('ROLE_' + user.roles[i].name.toUpperCase())
        }

        res.status(200).send({
            id: user._id,
            username: user.username,
            email: user.email,
            roles: authorities,
            accessToken: token
        })
    })

}