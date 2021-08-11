const express = require('express')
const Joi = require('joi')
const app = express()
require('dotenv').config()
const jwt = require('jsonwebtoken')
const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')


// Basic configuration
app.use(express.json())
app.use(express.urlencoded({extended: true}))

// Database connection
async function dbConnect() {
    try{
    await mongoose.connect(process.env.MONGO_URI, {useNewUrlParser: true, useUnifiedTopology: true})
    console.log('$$ DB Connection Successful $$')
    } catch (error) {
    console.log('!! DB Connection Failed !!')
    console.log(error)
    }
}

dbConnect()

// Database schema and model setup
const userSchema = mongoose.Schema({
    username: {type: String, required: true},
    email: {type: String, required: true},
    password: {type: String, required: true},
    joinDate: {type: Date, default: Date.now}
})

const User = mongoose.model('User', userSchema)


// User input validation schema for account creation
const JoiRegSchema = Joi.object({

    username: Joi.string()
    .alphanum()
    .min(3)
    .max(30)
    .required(),

    email: Joi.string()
    .email({ minDomainSegments: 2, tlds: { allow: ['com', 'net'] } })
    .required(),

    password: Joi.string()
    .min(6)
    .max(30)
    .required()

})

const JoiLogSchema = Joi.object({

    email: Joi.string()
    .email({ minDomainSegments: 2, tlds: { allow: ['com', 'net'] } })
    .required(),

    password: Joi.string()
    .min(6)
    .max(30)
    .required()

})

// JWT Authentication
function authenticateToken(req, res, next) {

    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (!token) {
        return res.status(401).send('ACCESS DENIED')
    } else {
        jwt.verify(token, process.env.SECRET, (err, decoded) => {
            if (err) return res.send('ACCESS DENIED')
            next()
        })
        }
}

// The root GET
app.get('/', (req, res) => {
    res.sendFile(process.cwd()+'/index.html')
})

// Registering a new user
app.post('/api/register', (req, res) => {
    let data = JoiRegSchema.validate(req.body)
    if ('error' in data) {
        return res.json(data.error.details[0].message)
    } else {
        User.findOne({email: req.body.email}, (err, cb) => {
            if (err) return console.log(err), res.status(500).send('server error, try again')
            if (cb === null) {
                let hash = bcrypt.hashSync(req.body.password, 8)
                let userData = {...req.body}
                userData.password = hash
                User.create(userData, (err, data) => {
                if (err) return console.error(err), res.status(500).send('server error, try again')
                     const cleaned = {
                         username: data.username,
                         email: data.email,
                         password: data.password,
                         joinDate: data.joinDate
                     }
                return res.json(cleaned)
                })
            } else {
                res.json({'error': 'User with the email already exist. Try another email.'})
            }
        })

    }

})


// User log-in and authentication
app.post('/api/login', (req, res) => {

    let data = JoiLogSchema.validate(req.body)
    if ('error' in data) {
        return res.json(data.error.details[0].message)
    } else {
        User.findOne({email: req.body.email}, (err, cb) => {
            if (err) return console.error(err), res.status(500).send('server error, try again')
            if (cb === null) return res.json({error: "wrong email or password"})
            let result = bcrypt.compareSync(req.body.password, cb.password)
            if (result === true) {
                let token = jwt.sign({email: cb.email}, process.env.SECRET)
                res.send(`Welcome  ${cb.username}, here's your token: BEARER ${token}`)
            } else {
                return res.json({error: "wrong email or password"})
            }
        })
    }
})

// GET the users with the token
app.get('/api/users', authenticateToken, (req, res) => {

    User.find({}, (err, data) => {
        if (err) return console.error(err)
        let data_arr = []
        data.forEach(function (item) {
            let temp = {}
            temp.username = item.username
            temp.email = item.email
            temp.joinDate = item.joinDate
            data_arr.push(temp)
        })

        res.send(data_arr)
    })

})


app.listen(process.env.PORT || 3000, () => {
    console.log('Server up and running.....')
})

