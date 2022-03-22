const b64 = require('base64-js');
const encryptionSdk = require('@aws-crypto/client-node');
const { APIClient, SendEmailRequest, RegionUS } = require("customerio-node");

// Copied from https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-lambda-custom-email-sender.html

// Configure the encryption SDK client with the KMS key from the environment variables.
const { decrypt } = encryptionSdk.buildClient(encryptionSdk.CommitmentPolicy.REQUIRE_ENCRYPT_ALLOW_DECRYPT);
const generatorKeyId = process.env.KEY_ALIAS;
const keyIds = [ process.env.KEY_ID ];
const keyring = new encryptionSdk.KmsKeyringNode({ generatorKeyId, keyIds })

module.exports.handler = async function(event, context) {
  const cio = new APIClient(process.env.CUSTOMER_IO_KEY, { region: RegionUS });

  // Decrypt the secret code using encryption SDK.
  let plainTextCode;
  if(event.request.code){
    const { plaintext } = await decrypt(keyring, b64.toByteArray(event.request.code));
    plainTextCode = plaintext
  }

  // PlainTextCode now has the decrypted secret.
  // plainTextCode.toString()
  const request = {
    to: event.request.userAttributes.email,
    identifiers: {
      id: event.request.userAttributes.sub,
    },
    message_data: {
      username: event.request.userAttributes.email,
      companyName: event.request.userAttributes['custom:company_name'],
      firstName: event.request.userAttributes.given_name,
    },
  }
  switch (event.triggerSource) {
    case 'CustomEmailSender_SignUp': {
      // Send email to end-user using custom or 3rd party provider.
      // Include temporary password in the email.
      request.transactional_message_id = process.env.SIGNUP_MESSAGE_ID;
      request.message_data.code = plainTextCode.toString();
      break;
    }
    case 'CustomEmailSender_ResendCode': {
      request.transactional_message_id = process.env.RESENDCODE_MESSAGE_ID;
      request.message_data.code = plainTextCode.toString();
      break;
    }
    case 'CustomEmailSender_ForgotPassword': {
      request.transactional_message_id = process.env.FORGOTPASSWORD_MESSAGE_ID;
      request.message_data.code = plainTextCode.toString();
      break;
    }
    case 'CustomEmailSender_UpdateUserAttribute': {
      request.transactional_message_id = process.env.UPDATEUSERATTRIBUTE_MESSAGE_ID;
      request.message_data.code = plainTextCode.toString();
      break;
    }
    case 'CustomEmailSender_VerifyUserAttribute': {
      request.transactional_message_id = process.env.VERIFYUSERATTRIBUTE_MESSAGE_ID;
      request.message_data.code = plainTextCode.toString();
      break;
    }
    case 'CustomEmailSender_AdminCreateUser': {
      request.transactional_message_id = process.env.ADMINCREATEUSER_MESSAGE_ID;
      request.message_data.tmpPass = plainTextCode.toString();
      break;
    }
    case 'CustomEmailSender_AccountTakeOverNotification': {
      request.transactional_message_id = process.env.ACCOUNTTAKEOVERNOTIFICATION_MESSAGE_ID;
      request.message_data.code = plainTextCode.toString();
      break;
    }
    default: {
      throw new Error('Unknown triggerSource passed'));
    }
  }

  await cio.sendEmail(new SendEmailRequest(request));
});
