const bcrypt = require("bcryptjs");
const userServices = require("../services/user.services");
const mysql = require('mysql');
const {db} = require('../config/db.config');

/**
 * 1. To secure the password, we are using the bcryptjs, It stores the hashed password in the database.
 * 2. In the SignIn API, we are checking whether the assigned and retrieved passwords are the same or not using the bcrypt.compare() method.
 * 3. In the SignIn API, we set the JWT token expiration time. Token will be expired within the defined duration.
 */
exports.register = (req, res, next) => {
  const { password } = req.body;

  const salt = bcrypt.genSaltSync(10);

  req.body.password = bcrypt.hashSync(password, salt);

  userServices.register(req.body, (error, results) => {
    if (error) {
      return next(error);
    }
    return res.status(200).send({
      message: "Success",
      data: results,
    });
  });
};

exports.login = (req, res, next) => {
  const { email, password } = req.body;

  userServices.login({ email, password }, (error, results) => {
    if (error) {
      return next(error);
    }
    return res.status(200).send({
      message: "Success",
      data: results,
    });
  });
};

exports.userProfile = (req, res, next) => {
  return res.status(401).json({ message: "Authorized User!!" });
};


exports.otpLogin = (req, res, next) => {
  userServices.createNewOTP(req.body, (error, results) => {
    if (error) {
      return next(error);
    }
    return res.status(200).send({
      message: "Success",
      token: results,
    });
  });
};

exports.verifyOTP = (req, res, next) => {
  userServices.verifyOTP(req.body, (error, access) => {
    if (error) {
      return next(error);
    }
    return res.status(200).send({
      message: "Success",
      access: access,
    });
  });
}

exports.location = (req, res)=> {
  const id=req.body.id;
  const name=req.body.name;
  const lat=req.body.lat;
  const long=req.body.long;

  db.query('insert into driver_details values (?, ?, ?, ?)',[id,name,lat,long],(err,result)=>{
     if(err)
      {
        console.log(err)
      }else{
        res.send("POSTED")
      }
   
  })
}

exports.tracking = (req,res) => {
  db.query("select * from driver_details",function(err,result,fields){
    if(err)
      {
        console.log(err)
      }else{
        res.send(result)
      }
  })
}







