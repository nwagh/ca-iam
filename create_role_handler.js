'use strict';

module.exports.create_cross_account_role = (event, context, callback) => {

  var AWS = require('aws-sdk');
  //Create IAM Service Object
  var iam = new AWS.IAM({apiversion : '2010-05-08'});
  //Parse Event attributes
  var principal = event.principal;
  var fromTimestamp = event.fromTimestamp;
  var toTimestamp = event.toTimestamp;
  var ticket_id = event.ticket_id;
  var policies = event.policies;
  var trust_account = event.trust_account;
  var target_account = event.target_account;

  var responseCode = 500;
  var responseStr;

  var arn = "arn:aws:iam::" + event.trust_account + ":root";


  var cross_account_trust = {
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "subARN"
      },
      "Action": "sts:AssumeRole",
      "Condition": {
        "DateLessThan": {
          //Format "2017-10-25T09:10:00-04:00"
          "aws:currentTime": "subToTimestamp"
        }
      }
    }
  ]
  }

  cross_account_trust.Statement[0].Condition.DateLessThan['aws:currentTime'] = toTimestamp;
  cross_account_trust.Statement[0].Principal.AWS = arn;

  var role_params = {
    AssumeRolePolicyDocument : JSON.stringify(cross_account_trust),
    Path: "/",
    RoleName: event.ticket_id
  };

  //Create new Role for Ticket
  iam.createRole(role_params,function(err,data){
    if(err){
      responseStr =  err.stack;
      console.log(err,err.stack);
    }else{
      responseCode = 200;
      console.log("Success :",data);
    }
  });

  const response = {
    statusCode: responseCode,
    body: JSON.stringify({
      message: responseStr,
      input: event
    }),
  };

  callback(null, response);

};
