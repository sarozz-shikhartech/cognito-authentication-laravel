<?php

namespace App\Http\Controllers;

use Aws\CognitoIdentityProvider\Exception\CognitoIdentityProviderException;
use Aws\Result;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response as ResponseAlias;

class CognitoController extends Controller
{

    /**
     * @param Request $request
     * @return JsonResponse|\Exception|array
     */
    public function login(Request $request): JsonResponse|\Exception|array
    {
        $validator = Validator::make($request->all(), [
            'username'     => 'required',
            'password'  => 'required',
        ]);
        if ($validator->fails()) return $this->output($validator->errors(), [], 422);

        $reqStore = $request->get('store');

        $data['email'] = $request->username;
        $data['password'] = $request->password;
        $data['awsCognitoPoolId'] = $reqStore ? $reqStore['pool_id'] : null;
        $data['awsClientId'] = $reqStore ? $reqStore['client_id'] : null;

        $response = $this->cognitoService->processCognitoAuthenticate($data);
        if ($response instanceof CognitoIdentityProviderException) {
            return $this->output('User not found.', $response->getMessage(), ResponseAlias::HTTP_INTERNAL_SERVER_ERROR);
        }

        if (array_key_exists('cognito_session', $response)) {
            return $this->output('Temporary Password Change Required.', $response, ResponseAlias::HTTP_ACCEPTED);
        }

        return $this->output('Authenticated.', $response);
    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function register(Request $request): JsonResponse
    {
        $name = $request->name ?? null;
        $email = $request->email ?? null;
        if (empty($name)) {
            return $this->output('Name field is empty.', [], ResponseAlias::HTTP_BAD_REQUEST);
        }
        if (empty($email)) {
            return $this->output('Email field is empty.', [], ResponseAlias::HTTP_BAD_REQUEST);
        }

        $cognitoResponse = $this->cognitoService->processCognitoAdminCreateUser($request);
        if (!$cognitoResponse instanceof Result) {
            return $this->output('Could not proceed with register.', $cognitoResponse->getMessage(), ResponseAlias::HTTP_INTERNAL_SERVER_ERROR);
        }

        $cognitoSubIndex = array_search("sub", array_column($cognitoResponse->get('User')["Attributes"], "Name"));
        $newUser = [
            'name' => $name,
            'email' => $email,
            'cognito_username' => $cognitoResponse->get('User')['Username'],
            'cognito_id' => $cognitoResponse->get('User')['Attributes'][$cognitoSubIndex]['Value']
        ];

        return $this->output('User Created. Email has been sent to respective email.', $newUser);
    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function changePassword(Request $request): JsonResponse
    {
        $email = $request->email ?? null;
        $newPassword = $request->password ?? null;
        if (empty($newPassword)) {
            return $this->output('Password field is empty.', [], ResponseAlias::HTTP_BAD_REQUEST);
        }
        if (empty($email)) {
            return $this->output('Email field is empty.', [], ResponseAlias::HTTP_BAD_REQUEST);
        }

        $res = $this->cognitoService->processCognitoUserPasswordChange($request);
        if ($res instanceof CognitoIdentityProviderException || $res != 200) {
            return $this->output('Password change failed.', $res->getMessage(), ResponseAlias::HTTP_INTERNAL_SERVER_ERROR);
        }

        return $this->output('Password update successful.');
    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function forgetPassword(Request $request): JsonResponse
    {
        $email = $request->email ?? null;
        if (empty($email)) {
            return $this->output('Email field is empty.', [], ResponseAlias::HTTP_BAD_REQUEST);
        }

        $res = $this->cognitoService->processForgetPassword($request);

        if ($res) {
            return $this->output('Success, we have forwarded password reset code to the respective mail.');
        } else {
            return $this->output('Forget password process failed.', [], ResponseAlias::HTTP_INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * @param Request $request
     * @return CognitoIdentityProviderException|\Exception|JsonResponse
     */
    public function forcePasswordChange(Request $request): JsonResponse|\Exception|CognitoIdentityProviderException
    {
        $email = $request->email ?? null;
        $password = $request->password ?? null;
        $cognito_session = $request->cognito_session ?? null;

        $awsClientId = $request->headers->get('aws_client_id');

        if (empty($email) || empty($password) || empty($cognito_session)) {
            return $this->output('Invalid request data.', [], ResponseAlias::HTTP_BAD_REQUEST);
        }

        $params = [
            'ChallengeName' => 'NEW_PASSWORD_REQUIRED',
            'ClientId' => $awsClientId,
            'ChallengeResponses' => [
                'USERNAME' => $email,
                'NEW_PASSWORD' => $password
            ],
            'Session' => $cognito_session
        ];

        $res = $this->cognitoService->processCognitoForcePasswordChange($params);

        if ($res instanceof CognitoIdentityProviderException) {
            return $this->output('Force password change process failed.', $res->getMessage(), ResponseAlias::HTTP_INTERNAL_SERVER_ERROR);
        }

        return $this->output('Password changed successfully.', $res);
    }

    public function resetPassword(Request $request): JsonResponse
    {
        $email = $request->email ?? null;
        $password = $request->password ?? null;
        $code = $request->code ?? null;
        if (empty($email) || empty($password) || empty($code)) {
            return $this->output('Invalid request data.', [], ResponseAlias::HTTP_BAD_REQUEST);
        }

        $res = $this->cognitoService->processResetPassword($request);

        if ($res instanceof CognitoIdentityProviderException) {
            return $this->output('Force password change process failed.', $res->getMessage(), ResponseAlias::HTTP_INTERNAL_SERVER_ERROR);
        }

        return $this->output('Password changed successfully.', $res);
    }
}
