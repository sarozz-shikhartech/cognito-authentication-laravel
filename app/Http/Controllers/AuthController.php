<?php

namespace App\Http\Controllers;

use App\Models\Cognito;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Symfony\Component\HttpFoundation\Response as ResponseAlias;

class AuthController extends Controller
{
    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function userLogin(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent());

        $validator = Validator::make($request->all(), [
            'email' => 'required',
            'password' => 'required'
        ]);
        if ($validator->fails()) return $this->output($validator->errors(), [], 422);

        $headers = $request->headers;
        $domain = $headers->get('domain');

        if (!$domain) {
            return $this->output('Err header: domain is missing.', [], 422);
        }

        $user = User::where([['email', '=', $data->email], ['store_url', '=', $domain], ['status', '1']])->first();
        if (!$user) {
            return $this->output('User not found', [], ResponseAlias::HTTP_UNAUTHORIZED);
        }

        $credentials = $request->only('email', 'password');
        $token = Auth::claims(['user_id' => $user->id, 'email' => $user->email, 'store_id' => $user->store_id])->attempt($credentials);
        if (!$token) {
            return $this->output('Invalid Credentials.', [], ResponseAlias::HTTP_UNAUTHORIZED);
        }

        return $this->output('Login Successfully', [
            'email' => $user->email,
            'name' => $user->name,
            'token' => $token
        ]);
    }

    /**
     * @param Request $request
     * @return JsonResponse
     */
    public function userRegister(Request $request): JsonResponse
    {
        $data = json_decode($request->getContent());

        $validator = Validator::make($request->all(), [
            'store_id' => 'required',
            'store_url' => 'required',
            'name' => 'required',
            'email' => 'required|email',
            'password' => 'required'
        ]);
        if ($validator->fails()) return $this->output($validator->errors(), [], 422);

        $storeName = $data->name;
        $email = $data->email;
        $password = $data->password;
        $storeId = $data->store_id;
        $storeUrl = $data->store_url;

        //check if request store is new or existing on
        $store = User::where('store_id', $storeId)->first();

        //if new register it and create cognito pool and client for it
        if (!$store) {
            try {
                $newUser = User::create([
                    'name'       => $storeName,
                    'email'      => $email,
                    'password'   => Hash::make($password),
                    'status'     => '1',
                    'store_id'   => $storeId,
                    'store_url'  => $storeUrl
                ]);

                if ($newUser) {
                    $token = Auth::claims(['user_id' => $newUser->id, 'email' => $newUser->email, 'store_id' => $newUser->store_id, 'store_url' => $newUser->store_url])
                        ->login($newUser);
                    if (!$token) return $this->output('Something went wrong', [], 500);

                    /*
                     * @todo create pool for the new store
                     */
                    $pool = $this->cognitoService->serviceCreatePool($storeId, $storeName);
                    if ($pool instanceof \Exception) return $this->output('Something went wrong', $pool->getMessage(), 500);

                    $userPoolId = $pool['UserPool']['Id'];
                    $userPoolName = $pool['UserPool']['Name'];

                    /*
                     * @todo create client for the new store
                     */
                    $client = $this->cognitoService->serviceCreateClientId($userPoolId, $storeId, $storeName);
                    if ($client instanceof \Exception) return $this->output('Something went wrong', $client->getMessage(), 500);

                    $clientId = $client['UserPoolClient']['ClientId'];;

                    $cognito = Cognito::create([
                        'store_id' => $storeId,
                        'user_id' => $newUser->id,
                        'pool_id' => $userPoolId,
                        'pool_name' => 'pool-' . $storeId . '-' . $storeName . '-' . time(),
                        'client_name' => $client['UserPoolClient']['ClientName'],
                        'client_id' => $clientId,
                    ]);
                    if (!$cognito) return $this->output('Error when creating cognito.', [], 500);

                    $data = [
                        "store_name" => $newUser->name,
                        "token" => $token,
                        "poolName" => $userPoolName,
                    ];

                    return $this->output('User created successfully.', $data);
                }
                return $this->output('User created failed.', [], 500);
            } catch (\Exception $exception) {
                return $this->output('Registration failed.', $exception->getMessage(), ResponseAlias::HTTP_INTERNAL_SERVER_ERROR);
            }
        }

        $store->status = $data->status ?? "0";
        $store->save();

        return $this->output('Store updated successfully.', []);
    }
}
