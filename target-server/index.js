import express from "express"
import { engine } from 'express-handlebars'
import fs from 'fs'
import session from 'express-session'
import { v4 } from 'uuid'
import cors from 'cors'
import flash from 'connect-flash-plus'

// Alternative to __dirname for node.js when use ES Modules 
import { dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));
// ----------------------------------------------------

const app = express()
const PORT = 3000


// CSRF

const tokens = new Map()

function csrfToken(sessionID) {
  const token = v4()
  tokens.get(sessionID).add(token)
  setTimeout(() => tokens.get(sessionID).delete(token),10000)
  return token
}

// DB
const users = JSON.parse(fs.readFileSync('db.json'))

// Middlewares
/* app.use(cors({
  origin: 'http://localhost:39549',
  credentials: true
}))*/ // this is the only way for the attacker to see the value of csrf token
app.use(express.urlencoded({ extended: true}))
app.use(flash())
app.use(session({
  resave: false,
  saveUninitialized: false,
  secret: 'test'
}))
app.set('view engine', 'hbs')

app.engine('hbs', engine({
  defaultLayout: 'main',
  layoutsDir: __dirname,
  extname: '.hbs'
}))

app.set('views', __dirname)

// Callbacks
function login(req,res,next) {
  if(req.session.userId){
    next()
  } else {
    res.redirect('/login')
  }
}

function csrf(req,res,next) {
  const token = req.body.token
  if(!token || !tokens.get(req.sessionID).has(req.body.token)){
    res.status(422).send('CSRF token missing or expired')
  } else {
    next()
  }
}

// Routes
app.get('/home', login, (req,res) => {
  res.send('Home')
})

app.get('/login', (req,res) => {
  console.log(req.session);
  res.render('login', { message: req.flash('message')})
})

app.post('/login', (req,res) => {
  if(!req.body.email || !req.body.password){
    req.flash('message', 'Fill all the fields')
    return res.redirect('/login')
  }
  const user = users.find(user => user.email === req.body.email)
  if(!user || user.password !== req.body.password){
    req.flash('message', 'Invalid credentials')
    return res.redirect('/login')
  } else {
    req.session.userId = user.id
    tokens.set(req.sessionID, new Set())
    res.redirect('home')
  }
})

app.get('/edit', login, (req,res) => {
  res.render('edit', {token: csrfToken(req.sessionID)})
})

app.post('/edit', login, csrf, (req,res) => {
  if(!req.body.email || !req.body.token){
    res.status(400).send('Invalid email')
  } else{
    const user = users.find(user => req.session.userId === user.id)
    user.email = req.body.email
    console.log(`User ${user.id} changed email to ${user.email}`);
    res.send('Email changed')
  }
})

app.get('/logout', (req,res) => {
  req.session.destroy()
  res.send('Logged out')
})
// Server
app.listen(PORT, console.log('Listening in http://localhost:' + PORT))