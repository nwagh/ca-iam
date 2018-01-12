'use strict';

module.exports.attach_policy = (event, context, callback) => {

  var payload = event.body;
  var AWS = require('aws-sdk');
  //Create IAM Service Object
  var iam = new AWS.IAM({apiversion : '2010-05-08'});
  //Parse Event attributes
  var principal = payload.principal;
  var fromTimestamp = payload.fromTimestamp;
  var toTimestamp = payload.toTimestamp;
  var ticket_id = payload.ticket_id;
  var policies = payload.policies;
  var trust_account = payload.trust_account;
  var target_account = payload.target_account;

  const response = (statusCode, message) => ({
    statusCode: statusCode,
    body: { message: message,
            input: payload }
  });

  var arn = "arn:aws:iam::" + payload.trust_account + ":root";

  var inline_deny_policy = {
    "Statement": [
        {
            "Effect": "Deny",
            "Action": [
                "*"
            ],
            "Resource": [
                "*"
            ],
            "Condition": {
                "DateGreaterThan": {
                    "aws:currentTime": "subToTimestamp"
                }
            }
        }
    ]
}

  inline_deny_policy.Statement[0].Condition.DateGreaterThan['aws:currentTime'] = toTimestamp;

  var inline_policy_params = {
    PolicyDocument: JSON.stringify(inline_deny_policy),
    PolicyName: 'AWSRevokeOlderSessions',
    RoleName: ticket_id
  };

  //Attach policy
  iam.putRolePolicy(inline_policy_params, function(err,data){
    if(err){
        callback(null, response(500, err.stack));
    }else{
        callback(null, response(200, data));
    }
  });


};
