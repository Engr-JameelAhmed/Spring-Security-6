package com.example.services;

import com.example.dto.JwtAuthenticationResponse;
import com.example.dto.RefreshTokenRequest;
import com.example.dto.SignInRequest;
import com.example.dto.SignUpRequest;
import com.example.entity.User;

public interface AuthenticationService {

    User signUp(SignUpRequest signUpRequest);
    JwtAuthenticationResponse signin(SignInRequest signInRequest);
    JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest);
}
