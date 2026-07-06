package com.identity.service;

import com.identity.dto.AuthResponseDto;
import com.identity.dto.LoginRequestDto;
import com.identity.dto.UserResponseDto;
import com.identity.entity.AuthUserEntity;
import com.identity.exception.AuthException;
import com.identity.jwt.JwtService;
import com.identity.repository.AuthUserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthLoginService {

    private final AuthUserRepository authUserRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;

    public AuthLoginService(AuthUserRepository authUserRepository,
                       JwtService jwtService,
                       PasswordEncoder passwordEncoder,
                       RefreshTokenService refreshTokenService) {
        this.authUserRepository = authUserRepository;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokenService = refreshTokenService;
    }

    public AuthResponseDto refresh(String refreshToken) {
        String userId = refreshTokenService.validateAndGetUserId(refreshToken);
        String newRefreshToken = refreshTokenService.rotate(refreshToken);
        String token = jwtService.generateToken(userId);

        var authUser = authUserRepository.findById(userId)
                .orElseThrow(() -> new AuthException("Invalid refresh token"));

        return new AuthResponseDto(
                token,
                newRefreshToken,
                new UserResponseDto(
                        authUser.getUserId(),
                        authUser.getEmail(),
                        null
                )
        );
    }

    public AuthResponseDto login(LoginRequestDto request) {

        var authUser = authUserRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new AuthException("Invalid credentials"));

        if (!passwordEncoder.matches(request.getPassword(), authUser.getPasswordHash())) {
            throw new AuthException("Invalid credentials");
        }

        String token = jwtService.generateToken(authUser.getUserId());
        String refreshToken = refreshTokenService.issueForUser(authUser.getUserId());

        return new AuthResponseDto(
                token,
                refreshToken,
                new UserResponseDto(
                        authUser.getUserId(),
                        authUser.getEmail(),
                        null
                )
        );
    }
}