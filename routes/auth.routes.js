const {verifySignup} = require('../middleware/')
const controller = require('../controllers/auth.controller')

module.exports = function(app) {
    app.use((req,res,next) => {
        // set header and allow use of x access token which we'll use to pass our token
        res.header(
            'Access-Control-Allow-Headers',
            'x-access-token, Origin, Content-type, Accept'
        )
        next()
    })

    app.post('/api/auth/signup', 
        [verifySignup.checkDuplicateUsernameorEmail, 
        verifySignup.checkRolesExisted], 
        controller.signup)

    app.post('/api/auth/signin', controller.signin)
}