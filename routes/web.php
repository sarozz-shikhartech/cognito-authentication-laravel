<?php

use App\Http\Controllers\AuthController;
use Illuminate\Support\Facades\Route;

Route::get('/', function () {
    return view('welcome');
});

Route::post('/app/login', [AuthController::class, 'userLogin']);
Route::post('/app/register', [AuthController::class, 'userRegister']);
