'use strict';

module.exports.attach_policy = (event, context, callback) => {

  var payload = event.body;
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

  const response = (statusCode, message) => ({
    statusCode: statusCode,
    body: { message: message,
            input: payload }
  });


  var policy_params = {
    PolicyArn: "",
    RoleName: ticket_id
  };

  //Attach policy
  policies.forEach(function(policy){
    policy_params.PolicyArn = policy;

    iam.attachRolePolicy(policy_params, function(err,data){
      if(err){
        callback(null, response(500, err.stack));
      }else{
        callback(null, response(200, data));
      }
    });

  });

};
