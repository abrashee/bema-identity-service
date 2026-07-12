package com.identity.service;

import com.identity.audit.SecurityAuditLogger;
import com.identity.dto.AuthResponseDto;
import com.identity.dto.AuthUserCreateRequest;
import com.identity.dto.UserResponseDto;
import com.identity.entity.AuthUserEntity;
import com.identity.entity.AuthUserRole;
import com.identity.exception.AuthException;
import com.identity.jwt.JwtService;
import com.identity.repository.AuthUserRepository;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;
import org.slf4j.MDC;

import java.util.Map;
import java.util.UUID;
import java.time.Duration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Service
public class AuthRegistrationService {

    private final AuthUserRepository authUserRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenService refreshTokenService;
    private final WebClient userServiceWebClient;
    private final SecurityAuditLogger auditLogger;
     private static final Logger log =
            LoggerFactory.getLogger(AuthRegistrationService.class);

    public AuthRegistrationService(
            AuthUserRepository authUserRepository,
            JwtService jwtService,
            PasswordEncoder passwordEncoder,
            RefreshTokenService refreshTokenService,
            @Qualifier("userServiceWebClient") WebClient userServiceWebClient,
            SecurityAuditLogger auditLogger
    ) {
        this.authUserRepository = authUserRepository;
        this.jwtService = jwtService;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokenService = refreshTokenService;
        this.userServiceWebClient = userServiceWebClient;
        this.auditLogger = auditLogger;
    }

    @Transactional
    public AuthResponseDto register(AuthUserCreateRequest request) {

        // 1. Prevent duplicate email early
        if (authUserRepository.findByEmail(request.email()).isPresent()) {
            auditLogger.failure(
                    "AUTH_REGISTRATION",
                    auditLogger.fingerprint(request.email()),
                    "DUPLICATE_ACCOUNT"
            );
            throw new AuthException("User already exists");
        }

        // 2. Create identity user
        AuthUserEntity entity = new AuthUserEntity();
        entity.setUserId(UUID.randomUUID().toString());
        entity.setEmail(request.email());
        entity.setPasswordHash(passwordEncoder.encode(request.password()));
        entity.setRole(AuthUserRole.USER);

        authUserRepository.save(entity);

        // 3. Sync with user-service. Fail closed so we do not issue tokens for
        // users whose profile could not be created.
        String internalToken = jwtService.generateInternalServiceToken("identity-service");
        try {
            String correlationId = MDC.get("correlationId");

            userServiceWebClient.post()
                    .uri("/api/users/internal")
                    .header("Authorization", "Bearer " + internalToken)
                    .headers(headers -> {
                        if (correlationId != null && !correlationId.isBlank()) {
                            headers.set("X-Correlation-ID", correlationId);
                        }
                    })
                    .bodyValue(Map.of(
                            "identityId", entity.getUserId(),
                            "email", entity.getEmail(),
                            "name", request.name()
                    ))
                    .retrieve()
                    .toBodilessEntity()
                    .block(Duration.ofSeconds(5));
        } catch (Exception ex) {
            log.warn(
                    "User-service sync failed for identityId={}",
                    entity.getUserId(),
                    ex
            );
            auditLogger.failure(
                    "AUTH_REGISTRATION",
                    entity.getUserId(),
                    "USER_PROFILE_SYNC_FAILED"
            );
            throw new AuthException("Registration temporarily unavailable");
        }

        // 4. Return something meaningful (not a magic string)
        String token = jwtService.generateUserToken(
                entity.getUserId(),
                entity.getRole().name()
        );
        String refreshToken = refreshTokenService.issueForUser(entity.getUserId());

        auditLogger.success("AUTH_REGISTRATION", entity.getUserId());

        return new AuthResponseDto(
                token,
                refreshToken,
                new UserResponseDto(
                        entity.getUserId(),
                        entity.getEmail(),
                        request.name(),
                        entity.getRole().name()
                )
        );
}
}
