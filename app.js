// IMPORTAÇÕES
require('dotenv').config()
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')
const User = require('./models/User')

// INICIALIZAÇÃO DAS CONFIGS
const app = express()
app.use(express.json())

// FUNÇÃO PARA CHECAR O TOKEN
function checkToken(req, res, next) {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(" ")[1]

    if (!token) {
        return res.status(401).json({
            message: 'Token not found'
        })
    }

    try {
        const secret = process.env.SECRET

        jwt.verify(token, secret)

        next()
    } catch (error) {
        return res.status(400).json({
            message: 'Invalid or expired token'
        })
    }
}

// ROTA INICIAL (PUBLICA)
app.get('/', (req, res) => {
    res.status(200).json({
        message: 'Welcome to our API!'
    })
})

// GET USER POR ID
app.get('/user/:id', checkToken, async (req, res) => {
    const id = req.params.id

    const user = await User.findById(id, '-password')

    if (user) {
        return res.status(200).json({
            message: 'User found successfully!',
            user
        }) 
    } else {
        return res.status(404).json({
            message: 'User not found!'
        }) 
    }
})

// CADASTRO DE UM NOVO USUARIO
app.post('/auth/register', async(req, res) => {
    const {name, email, password, confirmPassword } = req.body
    
    // VALIDAÇÕES DE CAMPOS PORCA SO PARA TESTE
    if (!name) {
        return res.status(422).json({ 
            message: 'Name is an invalid field!'
        })
    }

    if (!email) {
        return res.status(422).json({ 
            message: 'Email is an invalid field!'
        })
    }

    if (!password) {
        return res.status(422).json({ 
            message: 'Password is an invalid field!'
        })
    }

    if (password !== confirmPassword) {
        return res.status(422).json({ 
            message: 'Passwords do not match!'
        })
    }
    // FINAL VALIDAÇÕES DE CAMPOS PORCA SO PARA TESTE

    // VERIFICACAO DA EXISTENCIA DE UM USUARIO COM O MESMO EMAIL
    const userExist = await User.findOne({ email: email})

    if (userExist) {
        return res.status(422).json({
            message: 'Please, use another email!'
        })
    }

    // CRIAR SENHA CRIPTOGRAFADA
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    const user = new User({
        name,
        email,
        password: passwordHash
    })

    try {
        await user.save()
        res.status(201).json({
            message: 'User saved!'
        })
    } catch (error) {
        res.status(500).json({
            message: error
        })
    }
})

// LOGIN DE UM USUARIO
app.post('/auth/login', async (req, res) => {
    const {email, password } = req.body
    
    // VALIDAÇÕES DE CAMPOS PORCA SO PARA TESTE
    if (!email) {
        return res.status(422).json({ 
            message: 'Email is an invalid field!'
        })
    }

    if (!password) {
        return res.status(422).json({ 
            message: 'Password is an invalid field!'
        })
    }
    // FINAL VALIDAÇÕES DE CAMPOS PORCA SO PARA TESTE

    // CHECAR SE O USUARIO EXISTE NO BD
    const user = await User.findOne({ email: email })

    if (!user) {
        return res.status(404).json({
            message: 'User not found!'
        })
    }

    // CHECAR SE A SENHA BATE COM A SENHA DO BD CRIPTOGRAFADA
    const checkPassword = await bcrypt.compare(password, user.password)

    if (!checkPassword) {
        return res.status(404).json({ 
            message: 'User not found!'
        })
    }

    try {
        const secret = process.env.SECRET
        const token = jwt.sign(
            {
                id: user._id
            },
            secret,
        )

        res.status(200).json({
            message: 'User found successfully!',
            token
        })
    } catch (error) {
        return res.status(500).json({
            message: error
        })
    }
})

// VAR COM USUARIO E SENHA DE CONEXAO AO MONGO EM ARQUIVO LOCAL
const dbUSer = process.env.DB_USER
const dbPassword = process.env.DB_PASS

// CONEXAO COM O MONGODB UTILIZANDO O FRAMEWORK mongoose PARA FACILITAR A CONEXÃO
mongoose.connect(`mongodb://${dbUSer}:${dbPassword}@localhost:27017/admin`).then(() => {
    app.listen(3000)
    console.log('Connection successfully!')
}).catch((error) => {
    console.log(error)
})

