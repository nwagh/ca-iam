'use strict';

module.exports.attach_policy = (event, context, callback) => {

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

  var responseCode = 200;
  var responseStr;


  var policy_params = {
    PolicyArn: "",
    RoleName: event.ticket_id
  };

  //Attach policy
  policies.forEach(function(policy){
    policy_params.PolicyArn = policy;

    iam.attachRolePolicy(policy_params, function(err,data){
      if(err){
        responseStr = err.stack;
        console.log(err,err.stack);
        responseCode = 500;
      }else{
        responseStr =  data;
        responseCode = 200;
        console.log("policy successfully added");
        console.log("Success :",responseStr);
      }
    });

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
