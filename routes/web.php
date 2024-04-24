<?php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\CognitoController;
use App\Http\Middleware\Authenticate;
use App\Http\Middleware\CognitoValidator;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

Route::post('/app/login', [AuthController::class, 'userLogin']);
Route::post('/app/register', [AuthController::class, 'userRegister']);

Route::middleware([CognitoValidator::class])->group(function () {
    Route::controller(CognitoController::class)->group(function () {
        Route::post('/cognito-user/create', 'register');
        Route::post('/cognito-user/login', 'login');
        Route::post('/cognito-user/force-password-change', 'forcePasswordChange');
        Route::post('/cognito-user/forgot-password', 'forgetPassword');
        Route::post('/cognito-user/reset-password', 'resetPassword');
    });
});

Route::middleware([Authenticate::class])->group(function () {
    Route::controller(CognitoController::class)->group(function () {
        Route::post('/cognito-user/change-password', 'changePassword');
    });
});

