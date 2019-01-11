const express = require('express');
const expressLayouts = require('express-ejs-layouts');
const mongoose = require('mongoose');
const flash = require('connect-flash');
const session = require('express-session');
const passport = require('passport');

const app = express();

//passport config
require('./config/passport')(passport);

//DB config
const db = require('./config/keys').MongoURI;

//connect to Mongo
mongoose.connect(db, { useNewUrlParser: true })
.then( () => console.log('MongoDB connected')  )
.catch(err => console.log(err));

//ejs
app.use(expressLayouts);
app.set('view engine', 'ejs');

// Bodyparser to get data from the form with req.body
app.use(express.urlencoded({extended: false}));

// middleware Express session
app.use(session({
    secret: 'secret',
    resave: true,
    saveUninitialized: true
  }));

  // Passport middleware
  app.use(passport.initialize());
app.use(passport.session());

  //middlewear connect flash
  app.use(flash());

  //global variables
  app.use((req,res,next)=> {
      res.locals.success_msg = req.flash('success_msg');
      res.locals.error_msg = req.flash('error_msg');
      res.locals.error = req.flash('error');
      next();
  });

//routes
app.use('/', require('./routes/index.js'));
app.use('/users', require('./routes/users.js'));

const PORT = process.env.PORT || 5000;

app.listen(PORT, console.log(`Server started on port ${PORT}`));

