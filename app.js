var express    =  require('express');
var bodyParser =  require('body-parser');
var mongoose   =  require('mongoose');
var bcrypt     =  require('bcryptjs');
var session    =  require('express-session');
var userModel  =  require('./models/user');
var {check,validationResult} = require('express-validator');

//connect to db
mongoose.connect('mongodb://localhost:27017/session',{useNewUrlParser:true})
.then(()=>console.log('connected to database'))
.catch((error)=>console.log('error',error));

//init app
var app = express();

//set the template engine
app.set('view engine','ejs');

//fetch data from request
app.use(bodyParser.urlencoded({extended:false}));

//session
app.use(session({
    resave:true,
    saveUninitialized:true,
    secret:'yourSECRETKEY1234'
}));

//set local variable
app.use((req,res,next)=>{
    res.locals.auth = req.session.email;
    next();
});

//check session
var checkAuth = (req,res,next)=>{
    if(!req.session.email){
        res.redirect('/login');
    }else{
        next();
    }
}


//global variable
var eror=[];

//default page load
app.get('/',(req,res)=>{
    res.render('home');
});

app.get('/register',(req,res)=>{
    res.render('register',{err:{}});
});

app.post('/register',
check('email').isEmail().withMessage('Enter Valid EmailAddress'),
check('password').isLength(10).withMessage('Password Should Be 10 Character Long'),
(req,res)=>{
    var errors = validationResult(req);
    if(!errors.isEmpty()){
         res.render('register',{err:errors.array()});
    }else{
    bcrypt.genSalt(10, function(err, salt) {
        bcrypt.hash(req.body.password,salt, function(err, hash) {
            // Store hash in your password DB.
            var userr =  new userModel({
                email:req.body.email,
                password:hash
            });
            userr.save((err,data)=>{
                   if(err){
                       eror.push({msg:'email already exists'})
                       res.render('register',{err:eror});
                       eror.length=0;
                   }else{
                       res.redirect('/login');
                   }
            });
        });
    });
   }
});

app.get('/login',(req,res)=>{
    res.render('login',{err:{}});
});

app.post('/login',
check('email').isEmail().withMessage('Enter Valid EmailAddress'),
check('password').isLength(10).withMessage('Password Should Be 10 Character Long'),
(req,res)=>{
    var errors = validationResult(req);
    if(!errors.isEmpty()){
         res.render('register',{err:errors.array()});
    }else{
    userModel.find({email:req.body.email},(err,data)=>{
        if(err){
            console.log(err);
        }else{
            if(data!=''){
                console.log(data);
                bcrypt.compare(req.body.password,data[0].password, function(err, result) {
                    if(result){
                        req.session.email=data[0].email;
                        res.redirect('/profile');
                    }else{
                        eror.push({msg:'password didnt match'});
                        res.render('login',{err:eror});
                        eror.length=0;
                    }
                });
            }else{
                eror.push({msg:'user is not register'});
                res.render('login',{err:eror});
                eror.length=0;
            }
        }
    });
   }
});

//applying session authentication using checkAuth
app.get('/profile',checkAuth,(req,res)=>{
    res.render('profile',{email:req.session.email});
});

app.get('/logout',(req,res)=>{
    req.session.destroy();
    res.redirect('/login');
});

//assign port
var port =  process.env.PORT || 3000;
app.listen(port,()=>console.log('server run at '+port));