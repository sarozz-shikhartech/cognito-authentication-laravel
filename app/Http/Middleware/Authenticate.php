<?php

namespace App\Http\Middleware;

use App\Models\User;
use App\ResponseTrait;
use Closure;
use Illuminate\Contracts\Auth\Factory as Auth;
use Illuminate\Http\Request;
use PHPOpenSourceSaver\JWTAuth\Facades\JWTAuth;
use PHPOpenSourceSaver\JWTAuth\Token;
use Symfony\Component\HttpFoundation\Response;

class Authenticate
{
    use ResponseTrait;

    protected Auth $auth;

    /**
     * @param Auth $auth
     */
    public function __construct(Auth $auth)
    {
        $this->auth = $auth;
    }

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(Request): (Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        if ($request->header('authorization') && !empty($request->header('authorization'))) {
            $jwtToken = trim(str_replace("Bearer", "", $request->headers->get('Authorization')));
            try {
                $decodedToken = JWTAuth::manager()->decode(new Token($jwtToken));
                $user = User::where(['email' => $decodedToken['email'], 'id' => $decodedToken['user_id'], 'status' => '1'])
                    ->with('cognito')
                    ->first();

                //if member not found return unauthorized error
                if (!$user instanceof User) {
                    return $this->output('Invalid Access', [], Response::HTTP_UNAUTHORIZED);
                }

                //if valid member found the add id and email in event request
                $request->attributes->set('user', [
                    'id'        => $user->id,
                    'email'     => $user->email,
                    'name'      => $user->name,
                    'pool_id'   => $user->cognito ? $user->cognito->pool_id : null,
                    'client_id' => $user->cognito ? $user->cognito->client_id : null,
                ]);

                return $next($request);

            } catch (\Exception $exception) {
                return $this->output('Invalid or Expired Token', $exception->getMessage(), Response::HTTP_UNAUTHORIZED);
            }
        }

        return $this->output('No JWT Token', [], Response::HTTP_UNAUTHORIZED);
    }
}
