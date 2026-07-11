package com.identity.service;

import com.identity.dto.AuthResponseDto;
import com.identity.dto.LoginRequestDto;
import com.identity.dto.UserResponseDto;
import com.identity.entity.AuthUserEntity;
import com.identity.exception.AuthException;
import com.identity.jwt.JwtService;
import com.identity.repository.AuthUserRepository;
import com.identity.security.LoginBruteForceProtectionService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
public class AuthLoginService {

    private final AuthUserRepository authUserRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;
    private final LoginBruteForceProtectionService bruteForceProtectionService;

    public AuthLoginService(
            AuthUserRepository authUserRepository,
            JwtService jwtService,
            PasswordEncoder passwordEncoder,
            RefreshTokenService refreshTokenService,
            LoginBruteForceProtectionService bruteForceProtectionService
    ) {
        this.authUserRepository = authUserRepository;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokenService = refreshTokenService;
        this.bruteForceProtectionService = bruteForceProtectionService;
    }

    public AuthResponseDto refresh(String refreshToken) {
        String userId = refreshTokenService.validateAndGetUserId(refreshToken);

        var authUser = authUserRepository.findById(userId)
                .orElseThrow(() -> new AuthException("Invalid refresh token"));

        String newRefreshToken = refreshTokenService.rotate(refreshToken);
        String token = jwtService.generateUserToken(
                authUser.getUserId(),
                authUser.getRole().name()
        );

        return new AuthResponseDto(
                token,
                newRefreshToken,
                new UserResponseDto(
                        authUser.getUserId(),
                        authUser.getEmail(),
                        null,
                        authUser.getRole().name()
                )
        );
    }

    public AuthResponseDto login(LoginRequestDto request) {
        String email = request.getEmail();

        if (bruteForceProtectionService.isLocked(email)) {
            throw new AuthException("Invalid credentials");
        }

        var authUser = authUserRepository.findByEmail(email).orElse(null);

        if (authUser == null
                || !passwordEncoder.matches(
                        request.getPassword(),
                        authUser.getPasswordHash()
                )) {
            bruteForceProtectionService.recordFailure(email);
            throw new AuthException("Invalid credentials");
        }

        bruteForceProtectionService.recordSuccess(email);

        String token = jwtService.generateUserToken(
                authUser.getUserId(),
                authUser.getRole().name()
        );
        String refreshToken =
                refreshTokenService.issueForUser(authUser.getUserId());

        return new AuthResponseDto(
                token,
                refreshToken,
                new UserResponseDto(
                        authUser.getUserId(),
                        authUser.getEmail(),
                        null,
                        authUser.getRole().name()
                )
        );
    }
}