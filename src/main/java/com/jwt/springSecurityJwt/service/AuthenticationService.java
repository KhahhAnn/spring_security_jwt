package com.jwt.springSecurityJwt.service;

import com.jwt.springSecurityJwt.dto.JwtAuthenticationResponse;
import com.jwt.springSecurityJwt.dto.RefreshTokenRequest;
import com.jwt.springSecurityJwt.dto.SignUpRequest;
import com.jwt.springSecurityJwt.dto.SigninRequest;
import com.jwt.springSecurityJwt.entity.User;

public interface AuthenticationService {
    User signup(SignUpRequest signUpRequest);

    JwtAuthenticationResponse signIn(SigninRequest request);

    JwtAuthenticationResponse refreshToken(RefreshTokenRequest refreshTokenRequest);
}
