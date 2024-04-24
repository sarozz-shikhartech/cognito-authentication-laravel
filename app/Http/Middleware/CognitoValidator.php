<?php

namespace App\Http\Middleware;

use App\Models\Cognito;
use App\ResponseTrait;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpFoundation\Response as ResponseAlias;

class CognitoValidator
{
    use ResponseTrait;

    /**
     * Handle an incoming request.
     *
     * @param  \Closure(Request): (Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $headers = $request->headers;
        $domain = $headers->get('domain');

        if (!$domain) {
            return $this->output('Err header: domain is missing.', [], 422);
        }

        $cognito = Cognito::select('cognito.pool_id', 'cognito.client_id')
            ->join('users', function ($join) {
                $join->on('users.id', '=', 'cognito.user_id');
            })
            ->where('store_url', $domain)
            ->where('users.status', '1')
            ->first();
        if (!$cognito) return $this->output('Store config not found.',[], ResponseAlias::HTTP_INTERNAL_SERVER_ERROR);

        //if valid member found the add id and email in event request
        $request->attributes->set('store', [
            'pool_id' => $cognito->pool_id,
            'client_id' => $cognito->client_id
        ]);

        return $next($request);
    }
}
