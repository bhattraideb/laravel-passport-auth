<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Carbon\Carbon;
use App\User;
use App\Notifications\SignupActivate;

/**
 * Class AuthController
 * @package App\Http\Controllers
 * Refs: https://medium.com/modulr/create-api-authentication-with-passport-of-laravel-5-6-1dc2d400a7f
 * https://medium.com/techcompose/create-rest-api-in-laravel-with-authentication-using-passport-133a1678a876
 */

class AuthController extends Controller
{
    /**
     * Create user
     *
     * @param  [string] name
     * @param  [string] email
     * @param  [string] password
     * @param  [string] password_confirmation
     * @return [string] message
     */

    /**
     *POST http://127.0.0.1:8000/api/auth/signup
     * {
    "name":"Developer",
    "email": "developer@mail.com",
    "password": "admin1234",
    "password_confirmation": "admin1234"
    }
     *
     */

    public function signup(Request $request)
    {
        $request->validate([
            'name' => 'required|string',
            'email' => 'required|string|email|unique:users',
            'password' => 'required|string|confirmed'
        ]);
        $user = new User([
            'name' => $request->name,
            'email' => $request->email,
            'password' => bcrypt($request->password),
            'activation_token' => str_random(60)
        ]);
        $user->save();
        $user->notify(new SignupActivate($user));
        return response()->json([
            'message' => 'Successfully created user!'
        ], 201);
    }

    /**
     * Login user and create token
     *
     * @param  [string] email
     * @param  [string] password
     * @param  [boolean] remember_me
     * @return [string] access_token
     * @return [string] token_type
     * @return [string] expires_at
     */

    /**
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     *POST http://127.0.0.1:8000/api/auth/login
     * {
    "email": "developer@mail.com",
    "password": "admin1234",
    "remember_me": true
    }
     */
    public function login(Request $request)
    {
        $request->validate([
            'email' => 'required|string|email',
            'password' => 'required|string',
            'remember_me' => 'boolean'
        ]);
        $credentials = request(['email', 'password']);
        $credentials['active'] = 1;
        $credentials['deleted_at'] = null;

        if(!Auth::attempt($credentials))
            return response()->json([
                'message' => 'Unauthorized'
            ], 401);
        $user = $request->user();
        $tokenResult = $user->createToken('Personal Access Token');
        $token = $tokenResult->token;
        if ($request->remember_me)
            $token->expires_at = Carbon::now()->addWeeks(1);
        $token->save();
        return response()->json([
            'access_token' => $tokenResult->accessToken,
            'token_type' => 'Bearer',
            'expires_at' => Carbon::parse(
                $tokenResult->token->expires_at
            )->toDateTimeString()
        ]);
    }

    /**
     * Logout user (Revoke the token)
     *
     * @return [string] message
     */

    /**
     * @param Request $request
     * @return \Illuminate\Http\JsonResponse
     *
     * GET http://127.0.0.1:8000/api/auth/logout
     * Authorizatio: checked
     *Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImp0aSI6ImRkZWM3OGFhM2JmOTAwYTEyMjU2NjMwYmQwY2UzODc2NDE3MTk0NTk4MzlhNTZkZGM4MjViZDhiZDlhYWQ2N2NlZTc3MjVmZWY3NDQ0NmJiIn0.eyJhdWQiOiIxIiwianRpIjoiZGRlYzc4YWEzYmY5MDBhMTIyNTY2MzBiZDBjZTM4NzY0MTcxOTQ1OTgzOWE1NmRkYzgyNWJkOGJkOWFhZDY3Y2VlNzcyNWZlZjc0NDQ2YmIiLCJpYXQiOjE1MzE2NDAzODYsIm5iZiI6MTUzMTY0MDM4NiwiZXhwIjoxNTYzMTc2Mzg2LCJzdWIiOiIxIiwic2NvcGVzIjpbXX0.hw0CCQAIrNkDRMaLZhD5Gx9S1-P26drv77YlxrsNLmlzyb7vTj4wJD2UNxA_yDnWncw6tgloUb7EpTrcyfOQl_Pi7fbM2y2Mre00v-vzSRyLaFpP08C35-PCnMxzKGA8hJzFuyhg_zSHbatNhrCqAXevIWtXsEKUuaGg6s-ATlFynY5IQJ5lnKe6HoAWp5a6hQmeY840PkqrynmY0VsHlw9zwu5RHogXc1adTAiVC22vjH3nyCWuQ9yEEdnaCYASI0C3Ra6BlgBATc7NpQls8tO1h7v8S44NzvqsCZwcZdj6TwI9V-HIzyajl9yjk7cpW1SaNhkCFvDbQRKt27xdEXnAR444jrJdaXgGxStY03uELdDfMFimvNbLkai66_cae-rZufMbcs22A3t7OiSVSqhV6CpKzI2UP_2uOWukbDROeOv30G9uMSa_r9jKe8yTtyhr5tec4mfVNHbFN5qwyQSI8mzyBa29GPAXjKfIB87l9j2AT3uRK090WVf-OlCAZlBu6mscE5E_qZExQGSuDa4D-E6yY66Qy75_6bU_eCzYarQX11W7hO_DfrYpkEtdQ4s0ill7d1vsS_G9p5gVrgJpGq1swM5MnKrzFsPGbItsB8a7uxVyWfsiFHr964-9kxeqDh_nguHIGmFOKqwSui3tB63gRCtrQG4OmJyA7QM
     */

    public function logout(Request $request)
    {
        $request->user()->token()->revoke();
        return response()->json([
            'message' => 'Successfully logged out'
        ]);
    }

    /**
     * Get the authenticated User
     *
     * @return [json] user object
     */
    public function user(Request $request)
    {
        return response()->json($request->user());
    }

    public function signupActivate($token)
    {
        $user = User::where('activation_token', $token)->first();
        if (!$user) {
            return response()->json([
                'message' => 'This activation token is invalid.'
            ], 404);
        }
        $user->active = true;
        $user->activation_token = '';
        $user->save();
        return $user;
    }

}
