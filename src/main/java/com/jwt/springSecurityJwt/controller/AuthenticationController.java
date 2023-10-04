package com.jwt.springSecurityJwt.controller;

import com.jwt.springSecurityJwt.dto.JwtAuthenticationResponse;
import com.jwt.springSecurityJwt.dto.RefreshTokenRequest;
import com.jwt.springSecurityJwt.dto.SignUpRequest;
import com.jwt.springSecurityJwt.dto.SigninRequest;
import com.jwt.springSecurityJwt.entity.User;
import com.jwt.springSecurityJwt.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService authenticationService;


    @PostMapping("/signup")
    public ResponseEntity<User> signup(@RequestBody SignUpRequest signUpRequest) {
        return new ResponseEntity<User>(authenticationService.signup(signUpRequest), HttpStatus.OK);
    }

    @PostMapping("/signin")
    public ResponseEntity<JwtAuthenticationResponse> signin(@RequestBody SigninRequest signinRequest) {
        return new ResponseEntity<JwtAuthenticationResponse>(authenticationService.signIn(signinRequest), HttpStatus.OK);
    }

    @PostMapping("/refresh")
    public ResponseEntity<JwtAuthenticationResponse> refresh(@RequestBody RefreshTokenRequest refreshTokenRequest) {
        return new ResponseEntity<JwtAuthenticationResponse>(authenticationService.refreshToken(refreshTokenRequest), HttpStatus.OK);
    }
}
