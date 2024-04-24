<?php

namespace App\Http\Controllers;

use App\ResponseTrait;
use App\Services\CognitoService;

abstract class Controller
{
    use ResponseTrait;

    protected CognitoService $cognitoService;

    /**
     * @param CognitoService $cognitoService
     */
    public function __construct(CognitoService $cognitoService)
    {
        $this->cognitoService = $cognitoService;
    }
}
