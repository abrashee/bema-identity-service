package com.identity.controller;

import com.identity.audit.SecurityAuditLogger;
import com.identity.dto.ApiResponse;
import com.identity.dto.AuthResponseDto;
import com.identity.dto.AuthUserCreateRequest;
import com.identity.dto.LoginRequestDto;
import com.identity.dto.RefreshTokenRequestDto;
import com.identity.dto.LogoutRequestDto;
import com.identity.service.AuthRegistrationService;
import com.identity.service.AuthLoginService;
import com.identity.service.RefreshTokenService;
import com.identity.jwt.JwtService;
import com.identity.security.AccessTokenRevocationService;
import com.identity.exception.AuthException;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthLoginService authLoginService;
    private final AuthRegistrationService authRegistrationService;
    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;
    private final AccessTokenRevocationService accessTokenRevocationService;
    private final SecurityAuditLogger auditLogger;

    public AuthController(
            AuthLoginService authLoginService,
            AuthRegistrationService authRegistrationService,
            RefreshTokenService refreshTokenService,
            JwtService jwtService,
            AccessTokenRevocationService accessTokenRevocationService,
            SecurityAuditLogger auditLogger
    ) {
        this.authLoginService = authLoginService;
        this.authRegistrationService = authRegistrationService;
        this.refreshTokenService = refreshTokenService;
        this.jwtService = jwtService;
        this.accessTokenRevocationService = accessTokenRevocationService;
        this.auditLogger = auditLogger;
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<AuthResponseDto>> login(
            @Valid @RequestBody LoginRequestDto request
    ) {

        return ResponseEntity.ok(
                new ApiResponse<>(
                        "Login successful",
                        authLoginService.login(request)
                )
        );
    }

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<AuthResponseDto>> register(
            @Valid @RequestBody AuthUserCreateRequest request
    ) {

        return ResponseEntity.ok(
                new ApiResponse<>(
                        "Registration successful",
                        authRegistrationService.register(request)
                )
        );
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<AuthResponseDto>> refresh(
            @Valid @RequestBody RefreshTokenRequestDto request
    ) {

        return ResponseEntity.ok(
                new ApiResponse<>(
                        "Token refreshed",
                        authLoginService.refresh(request.refreshToken())
                )
        );
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Void>> logout(
            @Valid @RequestBody LogoutRequestDto request
    ) {
        JwtService.AccessTokenMetadata accessToken =
                jwtService.extractAccessTokenMetadata(request.accessToken());

        String refreshTokenUserId =
                refreshTokenService.validateAndGetUserId(request.refreshToken());

        if (!refreshTokenUserId.equals(accessToken.subject())) {
            throw new AuthException("Invalid logout token pair");
        }

        refreshTokenService.revokeAndGetUserId(request.refreshToken());
        accessTokenRevocationService.revoke(
                accessToken.tokenId(),
                accessToken.expiresAt()
        );

        auditLogger.success("AUTH_LOGOUT", accessToken.subject());

        return ResponseEntity.ok(
                new ApiResponse<>(
                        "Logout successful",
                        null
                )
        );
    }
}
