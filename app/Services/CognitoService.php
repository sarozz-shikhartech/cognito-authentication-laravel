<?php

namespace App\Services;

use App\ResponseTrait;
use Aws\CognitoIdentityProvider\CognitoIdentityProviderClient;
use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Aws\Credentials\Credentials;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Str;

class CognitoService
{
    use ResponseTrait;

    public function connectCognito(): CognitoIdentityProviderClient|\Exception|CognitoIdentityProviderException
    {
        try {
            return new CognitoIdentityProviderClient([
                'version' => 'latest',
                'region' => 'us-west-1',
                'credentials' => new Credentials(env('AWS_ACCESS_KEY'), env('AWS_SECRET_KEY'))
            ]);

        } catch (CognitoIdentityProviderException $exception) {
            return $exception;
        }
    }

    public function processCognitoAuthenticate($data): JsonResponse|\Exception|array
    {
        try {
            $client = $this->connectCognito();

            /*
             * https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminInitiateAuth.html
             */
            $response = $client->adminInitiateAuth([
                'AuthFlow' => 'ADMIN_NO_SRP_AUTH',
                'AuthParameters' => [
                    'USERNAME' => trim($data['email']),
                    'PASSWORD' => trim($data['password'])
                ],
                'ClientId' => $data['awsClientId'],
                'UserPoolId' => $data['awsCognitoPoolId']
            ]);

            $response = $response->toArray();

            if (array_key_exists('ChallengeName', $response) && $response['ChallengeName'] == 'NEW_PASSWORD_REQUIRED') {
                return ['cognito_session' => $response['Session'], 'email' => $data['email']];
            }

            $idToken = $response['AuthenticationResult']['IdToken'];

            // Get user information from idToken
            $payload = explode('.', $idToken)[1];
            $decodedPayload = base64_decode($payload);
            $userData = json_decode($decodedPayload);
            $cognitoUsername = $userData->{'cognito:username'};

            return ['cognito_username' => $cognitoUsername];
        } catch (\Exception $exception) {
            return $exception;
        }
    }

    public function processCognitoAdminCreateUser($request)
    {
        try {
            $name = $request->name;
            $email = $request->email;
            $email_verified = $request->email_verified ?? "false";

            $awsCognitoPoolId = $request->get('store')['pool_id'];

            $client = $this->connectCognito();

            /*
             * https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminCreateUser.html
             */
            return $client->adminCreateUser([
                "DesiredDeliveryMediums" => ["EMAIL"],
                "TemporaryPassword" => Str::password(12),
                "UserAttributes" => [
                    ["Name" => "name", "Value" => $name],
                    ["Name" => "email", "Value" => $email],
                    ["Name" => "email_verified", "Value" => $email_verified],
                ],
                "Username" => $email,
                "UserPoolId" => $awsCognitoPoolId,
            ]);

        } catch (CognitoIdentityProviderException $exception) {
            return $exception;
        }
    }

    public function processCognitoUserPasswordChange($request)
    {
        try {
            $email = $request->email;
            $currentPassword = $request->current_password;
            $newPassword = $request->new_password;

            $client = $this->connectCognito();

            $awsCognitoPoolId = $request->get('user')['pool_id'];
            $awsClientId = $request->get('user')['client_id'];

            $payload = [
                'AuthFlow' => 'ADMIN_NO_SRP_AUTH',
                'AuthParameters' => [
                    'USERNAME' => $email,
                    'PASSWORD' => $currentPassword,
                ],
                'ClientId' => $awsClientId,
                'UserPoolId' => $awsCognitoPoolId,
            ];

            /*
             * https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_AdminInitiateAuth.html
             */
            $response = $client->adminInitiateAuth($payload);

            // Extract tokens from callback request
            $accessToken = $response->toArray()['AuthenticationResult']['AccessToken'];

            /*
             * https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ChangePassword.html
             */
            $response = $client->changePassword([
                'AccessToken' => $accessToken,
                'PreviousPassword' => $currentPassword,
                'ProposedPassword' => $newPassword,
            ]);

            return $response->toArray()['@metadata']['statusCode'];

        } catch (CognitoIdentityProviderException $exception) {
            return $exception;
        }
    }

    public function processForgetPassword($request): bool
    {
        try {
            $awsClientId = $request->get('store')['client_id'];

            $client = $this->connectCognito();

            /*
             * https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ForgotPassword.html
             */
            $params = [
                "ClientId" => $awsClientId,
                "Username" => $request->email,
            ];
            $client->forgotPassword($params);

            return true;
        } catch (CognitoIdentityProviderException $exception) {
            return false;
        }
    }

    public function processCognitoForcePasswordChange($params = [])
    {
        try {
            $client = $this->connectCognito();

            /*
             * https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_RespondToAuthChallenge.html
             */
            $response = $client->respondToAuthChallenge($params);
            $response = $response->toArray();

            // Extract tokens from callback request
            $idToken = $response['AuthenticationResult']['IdToken'];

            // Get user information from idToken
            $payload = explode('.', $idToken)[1];
            $decodedPayload = base64_decode($payload);
            $userData = json_decode($decodedPayload);
            return $userData->{'cognito:username'};
        } catch (CognitoIdentityProviderException $exception) {
            return $exception;
        }

    }

    public function processResetPassword($request): CognitoIdentityProviderClient|\Exception|string|CognitoIdentityProviderException
    {
        try {
            $awsClientId = $request->get('store')['client_id'];

            $client = $this->connectCognito();

            /*
             * https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ConfirmForgotPassword.html
             */
            $params = [
                'ClientId' => $awsClientId,
                'Username' => $request->email,
                'Password' => $request->password,
                'ConfirmationCode' => $request->code
            ];
            $client->confirmForgotPassword($params);
            return $client;
        } catch (CognitoIdentityProviderException $exception) {
            return $exception;
        }

    }

    public function serviceCreatePool($storeId, $storeName)
    {
        /*
         * https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPool.html
         */
        try {
            $storeName = str_replace(' ', '_', $storeName);

            $client = $this->connectCognito();
            return $client->createUserPool([
                //name of the pool i.e. pool-1-testStore-1123456
                'PoolName' => 'pool-' . $storeId . '-' . $storeName . '-' . time(),
                //configuration for admin of this pool
                'AdminCreateUserConfig' => [
                    //if true then only the admin is allowed to create user profiles. set to false if users can sign themselves up via an app
                    'AllowAdminCreateUserOnly' => true,
                ],
                //policies associated with the new user pool
                'Policies' => [
                    //rules for users password requirement
                    'PasswordPolicy' => [
                        'MinimumLength' => 8, //required least minimum of 8 words in password
                    ],
                ],
                //array of schema attributes for the new user pool. moreover like columns in database table
                'Schema' => [
                    [
                        'AttributeDataType' => 'String', //datatype that the field will hold
                        'Mutable' => true, //is it editable
                        'Name' => 'store_name',//field name
                        'Required' => false, //nullable or not
                    ],
                    [
                        "AttributeDataType" => "String",
                        "Mutable" => false, //false which means it cannot be updated once set
                        "Name" => "email",
                        "Required" => true,
                    ]
                ],
                "UsernameConfiguration" => [
                    "CaseSensitive" => false
                ],
                //Specifies whether a user can use an email address or phone number as a username when they sign up.
                "UsernameAttributes" => ["email"],
            ]);
        } catch (CognitoIdentityProviderException $exception) {
            return $exception;
        }
    }

    public function serviceCreateClientId($userPoolId, $storeId, $storeName)
    {
        try {
            $storeName = str_replace(' ', '_', $storeName);
            $client = $this->connectCognito();

            /*
             * https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserPoolClient.html
             */
            return $client->createUserPoolClient([
                //name of the client
                'ClientName' => 'client-' . $storeId . '-' . $storeName . '-' . time(),
                'UserPoolId' => $userPoolId,
                //desired authentication flows that user pool client to support.
                'ExplicitAuthFlows' => [
                    'ALLOW_ADMIN_USER_PASSWORD_AUTH', //Enable admin based user password authentication flow
                    'ALLOW_CUSTOM_AUTH', //Enable Lambda trigger based authentication.
                    'ALLOW_USER_SRP_AUTH', //Enable SRP-based authentication.
                    'ALLOW_REFRESH_TOKEN_AUTH', //Enable auth-flow to refresh tokens.
                ],
                //config to specify whether you want to generate a secret for the user pool client being created.
                'GenerateSecret' => false,
                'RefreshTokenValidity' => 30,
                //if ENABLED and user doesn't exist, then authentication returns an error indicating either the username or password was incorrect. else in LEGACY, returns a UserNotFoundException exception
                'PreventUserExistenceErrors' => 'ENABLED'
            ]);
        } catch (\Exception $exception) {
            return $exception;
        }
    }
}
