const express = require('express')
const crypto = require('crypto')
const jwt = require('jsonwebtoken')
const Users = require('../models/Users')
const { isAuthenticated } = require('../auth')

const router = express.Router()

const signToken = id => {
	return jwt.sign(({ id }), 'parabailarlabambasenecesitaunapocodegracia', {
		expiresIn: 60, //1 min for testing purposes
	})
}

router.post('/register', (req, res) => {
	const { email, password } = req.body
	crypto.randomBytes(16, (err, salt) => {
		const newSalt = salt.toString('base64')
		crypto.pbkdf2(password, newSalt, 10000, 64, 'sha1', (err, key) => {
			const encryptedPwd = key.toString('base64')
			Users.findOne({ email }).exec()
				.then(user => {
					if(user){
						return res.send('Nombre de usuario no disponible')
					}
					Users.create({
						email,
						password: encryptedPwd,
						salt: newSalt,
					}).then(() => {
						res.send('Usuario creado con exito')
					})
				})
		})
	})
})

router.post('/login', (req, res) => {
	const { email, password } = req.body
	Users.findOne({ email }).exec()
		.then(user => {
			if(!user) {
				return res.send('Usuario y/o contraseña incorrectos')
			}
			crypto.pbkdf2(password, user.salt, 10000, 64, 'sha1', (err, key) => {
				const encryptedPwd = key.toString('base64')
				if(user.password === encryptedPwd) {
					const token = signToken(user._id)
					return res.send({ token })
				}
				res.sent('Usuario y/o constraseña incorrectos')
			})
		})
})

router.get('/me', isAuthenticated, (req, res) => {
	res.send(req.user)
})

module.exports = router

