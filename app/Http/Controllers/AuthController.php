<?php

namespace App\Http\Controllers;

use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Validator;
use Illuminate\Validation\ValidationException;
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

        $user = User::where('email', '=', $data->email)->first();
        if (!$user) {
            return $this->output('User not found', [], ResponseAlias::HTTP_UNAUTHORIZED);
        }

        $credentials = $request->only('email', 'password');
        $token = Auth::claims(['user_id' => $user->id, 'email' => $user->email])->attempt($credentials);
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

        $validator = Validator::make($request->all, [
            'store_id' => 'required',
            'name' => 'required',
            'email' => 'required|email|unique:users',
            'password' => 'required'
        ]);
        if ($validator->fails()) return $this->output($validator->errors(), [], 422);

        $name = $data->name;
        $email = $data->email;
        $password = $data->password;

        try {
            $newUser = User::create([
                'name'       => $name,
                'email'      => $email,
                'password'   => Hash::make($password),
                'status'     => '1'
            ]);

            if ($newUser) {
                $token = Auth::claims(['user_id' => $newUser->id, 'email' => $newUser->email])->login($newUser);
                if (!$token) return $this->output('Something went wrong', [], 500);

                $data = [
                    "store_name" => $newUser->name,
                    "token" => $token
                ];

                return $this->output('User created successfully.', $data, 500);

            }

            return $this->output('User created failed.', [], 500);
        } catch (\Exception $exception) {
            return $this->output('Registration failed.', $exception->getMessage(), ResponseAlias::HTTP_INTERNAL_SERVER_ERROR);
        }
    }
}
