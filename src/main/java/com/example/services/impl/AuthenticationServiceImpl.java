package com.example.services.impl;

import com.example.dto.JwtAuthenticationResponse;
import com.example.dto.RefreshTokenRequest;
import com.example.dto.SignInRequest;
import com.example.dto.SignUpRequest;
import com.example.entity.Role;
import com.example.entity.User;
import com.example.repository.UserRepository;
import com.example.services.AuthenticationService;
import com.example.services.JWTService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.HashMap;

@Service
@RequiredArgsConstructor
public class AuthenticationServiceImpl implements AuthenticationService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JWTService jwtService;
     public User signUp(SignUpRequest signUpRequest){
        User user = new User();

        user.setEmail(signUpRequest.getEmail());
        user.setFirstname(signUpRequest.getFirstName());
        user.setSecondname(signUpRequest.getLastName());
        user.setRole(Role.USER);
        user.setPassword(passwordEncoder.encode(signUpRequest.getPassword()));

        return userRepository.save(user);
     }

     public JwtAuthenticationResponse signin(SignInRequest signInRequest){
         authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(signInRequest.getEmail(), signInRequest.getPassword()));

         User user = userRepository.findByEmail(signInRequest.getEmail()).orElseThrow(() -> new IllegalArgumentException("Invalid email or password"));
         String jwt = jwtService.generateToken(user);
         String refreshToken = jwtService.generateRefreshToken(new HashMap<>(), user);

        JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();
        jwtAuthenticationResponse.setToken(jwt);
        jwtAuthenticationResponse.setRefreshToken(refreshToken);
        return jwtAuthenticationResponse;
     }

     public JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest){
         String userEmail = jwtService.extractUserName(refreshTokenRequest.getToken());

         User user = userRepository.findByEmail(userEmail).orElseThrow();
         if (jwtService.isTokenValid(refreshTokenRequest.getToken(), user)){
             String jwt = jwtService.generateToken(user);
             JwtAuthenticationResponse jwtAuthenticationResponse = new JwtAuthenticationResponse();
             jwtAuthenticationResponse.setToken(jwt);
             jwtAuthenticationResponse.setRefreshToken(refreshTokenRequest.getToken());
             return jwtAuthenticationResponse;
         }
         return null;
     }


}
