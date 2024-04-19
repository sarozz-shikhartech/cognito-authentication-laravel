<?php

namespace App;

use Illuminate\Http\JsonResponse;
use Symfony\Component\HttpFoundation\Response as ResponseAlias;

trait ResponseTrait
{
    public function output($message = null, $content = [],  $status = ResponseAlias::HTTP_OK): JsonResponse
    {
        $response = [
            'status' => $status === ResponseAlias::HTTP_OK ? "success" : "error",
            'message' => $message,
            'data' => $content
        ];

        return \response()->json($response, $status);
    }
}
