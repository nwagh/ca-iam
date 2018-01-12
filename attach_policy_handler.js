'use strict';

module.exports.attach_policy = (event, context, callback) => {

  var payload = event.body;
  var AWS = require('aws-sdk');
  //Create IAM Service Object
  var iam = new AWS.IAM({apiversion : '2010-05-08'});
  //Parse Event attributes
  var ticket_id = payload.ticket_id;
  var policy = payload.policy;


  const response = (statusCode, message) => ({
    statusCode: statusCode,
    body: { message: message,
            input: payload }
  });


  var policy_params = {
    PolicyArn: policy,
    RoleName: ticket_id
  };

  //Attach policy
  iam.attachRolePolicy(policy_params, function(err,data){
      if(err){
        console.log(err, err.stack)
        callback(null, response(500, err.stack));
      }else{
        console.log(data);
        callback(null, response(200, data ));
      }
    });




};
