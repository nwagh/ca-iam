'use strict';

module.exports.create_cross_account_role = (event, context, callback) => {

  var payload = event.body;
  var AWS = require('aws-sdk');
  //Create IAM Service Object
  var iam = new AWS.IAM({apiversion : '2010-05-08'});
  //Parse Event attributes

  var principal = payload.principal;
  var fromTimestamp = payload.fromTimestamp;
  var toTimestamp = payload.toTimestamp;
  var ticket_id = payload.ticket_id;
  var trust_account = payload.trust_account;
  var target_account = payload.target_account;

  const response = (statusCode, message) => ({
    statusCode: statusCode,
    body: { message: message,
            input: payload }
  });

  var arn = "arn:aws:iam::" + payload.trust_account + ":root";


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
    Path : "/",
    RoleName : payload.ticket_id
  };

  console.log("role_params :" + role_params.RoleName);

  //Create new Role for Ticket
  iam.createRole(role_params,function(err,data){
    if(err){
      callback(null, response(500, err.stack));

    }else{
      callback(null, response(200, data));
    }
  });



};
