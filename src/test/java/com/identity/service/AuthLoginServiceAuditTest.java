package com.identity.service;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.Optional;

import com.identity.audit.SecurityAuditLogger;
import com.identity.dto.LoginRequestDto;
import com.identity.entity.AuthUserEntity;
import com.identity.entity.AuthUserRole;
import com.identity.exception.AuthException;
import com.identity.jwt.JwtService;
import com.identity.repository.AuthUserRepository;
import com.identity.security.LoginBruteForceProtectionService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

class AuthLoginServiceAuditTest {

    private AuthUserRepository repository;
    private JwtService jwtService;
    private PasswordEncoder passwordEncoder;
    private RefreshTokenService refreshTokenService;
    private LoginBruteForceProtectionService bruteForceProtectionService;
    private SecurityAuditLogger auditLogger;
    private AuthLoginService service;

    @BeforeEach
    void setUp() {
        repository = mock(AuthUserRepository.class);
        jwtService = mock(JwtService.class);
        passwordEncoder = mock(PasswordEncoder.class);
        refreshTokenService = mock(RefreshTokenService.class);
        bruteForceProtectionService =
                mock(LoginBruteForceProtectionService.class);
        auditLogger = mock(SecurityAuditLogger.class);

        service = new AuthLoginService(
                repository,
                jwtService,
                passwordEncoder,
                refreshTokenService,
                bruteForceProtectionService,
                auditLogger
        );
    }

    @Test
    void auditsSuccessfulLogin() {
        AuthUserEntity user = user();

        when(repository.findByEmail("user@example.com"))
                .thenReturn(Optional.of(user));
        when(passwordEncoder.matches("valid-password", "hash"))
                .thenReturn(true);
        when(jwtService.generateUserToken("user-1", "USER"))
                .thenReturn("access-token");
        when(refreshTokenService.issueForUser("user-1"))
                .thenReturn("refresh-token");

        service.login(
                new LoginRequestDto(
                        "user@example.com",
                        "valid-password"
                )
        );

        verify(auditLogger).success("AUTH_LOGIN", "user-1");
    }

    @Test
    void auditsInvalidCredentialsWithoutRawEmail() {
        when(repository.findByEmail("missing@example.com"))
                .thenReturn(Optional.empty());
        when(auditLogger.fingerprint(anyString()))
                .thenReturn("sha256:fingerprint");

        assertThrows(
                AuthException.class,
                () -> service.login(
                        new LoginRequestDto(
                                "missing@example.com",
                                "valid-password"
                        )
                )
        );

        verify(auditLogger).failure(
                "AUTH_LOGIN",
                "sha256:fingerprint",
                "INVALID_CREDENTIALS"
        );
    }

    @Test
    void auditsLockedLoginAttempt() {
        when(bruteForceProtectionService.isLocked("user@example.com"))
                .thenReturn(true);
        when(auditLogger.fingerprint("user@example.com"))
                .thenReturn("sha256:fingerprint");

        assertThrows(
                AuthException.class,
                () -> service.login(
                        new LoginRequestDto(
                                "user@example.com",
                                "valid-password"
                        )
                )
        );

        verify(auditLogger).denied(
                "AUTH_LOGIN",
                "sha256:fingerprint",
                "ACCOUNT_LOCKED"
        );
    }

    @Test
    void auditsSuccessfulTokenRefresh() {
        AuthUserEntity user = user();

        when(refreshTokenService.validateAndGetUserId("refresh-token"))
                .thenReturn("user-1");
        when(repository.findById("user-1"))
                .thenReturn(Optional.of(user));
        when(refreshTokenService.rotate("refresh-token"))
                .thenReturn("new-refresh-token");
        when(jwtService.generateUserToken("user-1", "USER"))
                .thenReturn("new-access-token");

        service.refresh("refresh-token");

        verify(auditLogger).success(
                "AUTH_TOKEN_REFRESH",
                "user-1"
        );
    }

    private AuthUserEntity user() {
        AuthUserEntity user = new AuthUserEntity();
        user.setUserId("user-1");
        user.setEmail("user@example.com");
        user.setPasswordHash("hash");
        user.setRole(AuthUserRole.USER);
        return user;
    }
}
