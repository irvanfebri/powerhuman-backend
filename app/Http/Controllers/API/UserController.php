<?php

namespace App\Http\Controllers\API;

use App\Helpers\ResponseFormatter;
use Exception;
use Illuminate\Http\Request;
use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Laravel\Fortify\Rules\Password;


class UserController extends Controller
{
    public function login(Request $request)
    {
        try {       
        //Validate request 
        $request->validate([
            'email' => 'required|email',
            'password' => 'required',
        ]);


        //Find user by email
        $credentials = request(['email','password']);
        if(!Auth::attempt($credentials)){
            return ResponseFormatter::error('Unauthorized', 401);
        }
        

        $user = User::where('email',$request->email)->first();
        if (!Hash::check($request->password, $user->password)){
            throw new Exception ('Invalid password');
        }


        //Generate token
        $toketResult = $user->createToken('authToken')->plainTextToken;

        //Return response
       return ResponseFormatter::success([
        'access_token' => $toketResult,
        'token_type' => 'Bearer',
        'user' => $user
       ], 'Login Sucess');
} catch (Exception $e) {
    return ResponseFormatter::error('Authentication Failed');
}

    }

public function register(Request $request) {
    try {
        //Validate request
        $request->validate([
            'name' => ['required','string','max:255'],
            'email' => ['required','string','email','max:255','unique:users'],
            'password' => ['required','string',new Password],
        ]);

        //Create User 
        $user = User::create([
            'name' => $request->name,
            'email' => $request->email,
            'password' => Hash::make($request->password),
        ]);

        //Generate Token
        $tokenResult = $user->createToken('authToken')->plainTextToken;

        //Return response
        return ResponseFormatter::success([
            'access_token' => $tokenResult,
            'token_type' => 'Bearer',
            'user' => $user
           ], 'Login Sucess');
    } catch (Exception $e) {
        return ResponseFormatter::error('Authentication Failed');
    }
   

        //Return error response
        return ResponseFormatter::error($error->getMessage());
}

}

