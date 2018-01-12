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

  var arn = "arn:aws:iam::" + event.trust_account + ":root";

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
    RoleName: event.ticket_id
  };

  //Attach policy
  iam.putRolePolicy(inline_policy_params, function(err,data){
    if(err){
      responseStr = err.stack;
      console.log(err,err.stack);
      responseCode = 500;
    }else{
      responseStr =  data;
      responseCode = 200;
      console.log("Inline policy successfully added");
      console.log("Success :",responseStr);
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
