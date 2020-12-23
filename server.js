const express = require('express')
const bodyParser = require('body-parser')
const dbConfig = require('./config/db.config')
const cors = require('cors')
const PORT = process.env.PORT || 8080

const app = express()

app.use(cors())

// parse requests of content-type - application/json // allows for req.body
app.use(bodyParser.json())

// parse request of content type = application/x-www-form-encoded
app.use(bodyParser.urlencoded({extended: true}))

// SETUP MONGOOSE
const db = require('./models/index')
const Role = db.role

db.mongoose
    .connect(`mongodb://${dbConfig.HOST}:${dbConfig.PORT}/${dbConfig.DB}`,{
        useNewUrlParser: true,
        useUnifiedTopology: true
    })
    .then(()=> {
        console.log('Successfully connected to MongoDB')
        initial()
    })
    .catch(err => {
        console.error('Connection error', err)
        process.exit
    })

app.get('/',(req,res)=>{
    res.json({message: 'Welcome to the jungle. We\'ve got fun and games'})
})

// import the user and admin routes
require('./routes/auth.routes')(app)
require('./routes/user.routes')(app)

app.listen(PORT, ()=>{
    console.log(`Server running on port ${PORT}`)
})

function initial(){
    Role.estimatedDocumentCount((err, count)=>{
        // if no roles are present, create new roles (admin and user)
        if(!err && count === 0){
            new Role({
                name: 'user'
            }).save(err => {
                if(err) {
                    console.log('error',err)
                }
                console.log('added users to roles collection')
            })

            new Role({
                name: 'admin'
            }).save(err => {
                if(err) {
                    console.log('error',err)
                }
                console.log('added admin to roles collection')
            })
        }
    })
}