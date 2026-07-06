package com.identity.controller;

import com.identity.dto.ApiResponse;
import com.identity.dto.AuthResponseDto;
import com.identity.dto.AuthUserCreateRequest;
import com.identity.dto.LoginRequestDto;
import com.identity.dto.RefreshTokenRequestDto;
import com.identity.dto.LogoutRequestDto;
import com.identity.service.AuthRegistrationService;
import com.identity.service.AuthLoginService;
import com.identity.service.RefreshTokenService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthLoginService authLoginService;
    private final AuthRegistrationService authRegistrationService;
    private final RefreshTokenService refreshTokenService;

    public AuthController(AuthLoginService authLoginService,
                          AuthRegistrationService authRegistrationService,
                          RefreshTokenService refreshTokenService) {
        this.authLoginService = authLoginService;
        this.authRegistrationService = authRegistrationService;
        this.refreshTokenService = refreshTokenService;
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
        refreshTokenService.revoke(request.refreshToken());

        return ResponseEntity.ok(
                new ApiResponse<>(
                        "Logout successful",
                        null
                )
        );
    }
}
