package com.identity.config;

import com.identity.entity.AuthUserEntity;
import com.identity.entity.AuthUserRole;
import com.identity.repository.AuthUserRepository;
import com.identity.jwt.JwtService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.reactive.function.client.WebClient;

import java.time.Duration;
import java.util.Map;
import java.util.UUID;

@Component
public class AdminBootstrapRunner implements ApplicationRunner {

    private static final Logger log =
            LoggerFactory.getLogger(AdminBootstrapRunner.class);

    private final boolean enabled;
    private final String email;
    private final String password;
    private final String name;
    private final AuthUserRepository authUserRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final WebClient userServiceWebClient;

    public AdminBootstrapRunner(
            @Value("${bootstrap.admin.enabled:false}") boolean enabled,
            @Value("${bootstrap.admin.email:}") String email,
            @Value("${bootstrap.admin.password:}") String password,
            @Value("${bootstrap.admin.name:}") String name,
            AuthUserRepository authUserRepository,
            PasswordEncoder passwordEncoder,
            JwtService jwtService,
            @Qualifier("userServiceWebClient") WebClient userServiceWebClient
    ) {
        this.enabled = enabled;
        this.email = email == null ? "" : email.trim();
        this.password = password == null ? "" : password;
        this.name = name == null ? "" : name.trim();
        this.authUserRepository = authUserRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtService = jwtService;
        this.userServiceWebClient = userServiceWebClient;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        if (!enabled) {
            log.info("Administrator bootstrap is disabled");
            return;
        }

        validateConfiguration();

        if (authUserRepository.existsByRole(AuthUserRole.ADMIN)) {
            log.info("Administrator bootstrap skipped because an administrator already exists");
            return;
        }

        if (authUserRepository.findByEmail(email).isPresent()) {
            throw new IllegalStateException(
                    "Bootstrap administrator email already belongs to a non-admin account"
            );
        }

        AuthUserEntity admin = new AuthUserEntity();
        admin.setUserId(UUID.randomUUID().toString());
        admin.setEmail(email);
        admin.setPasswordHash(passwordEncoder.encode(password));
        admin.setRole(AuthUserRole.ADMIN);

        authUserRepository.save(admin);

        String internalToken =
                jwtService.generateInternalServiceToken("identity-service");

        try {
            userServiceWebClient.post()
                    .uri("/api/users/internal")
                    .header("Authorization", "Bearer " + internalToken)
                    .bodyValue(Map.of(
                            "identityId", admin.getUserId(),
                            "email", admin.getEmail(),
                            "name", name
                    ))
                    .retrieve()
                    .toBodilessEntity()
                    .block(Duration.ofSeconds(5));
        } catch (Exception ex) {
            throw new IllegalStateException(
                    "Unable to create bootstrap administrator profile",
                    ex
            );
        }

        log.info(
                "Bootstrap administrator created for configured email"
        );
    }

    private void validateConfiguration() {
        if (email.isBlank()) {
            throw new IllegalStateException(
                    "BOOTSTRAP_ADMIN_EMAIL is required when administrator bootstrap is enabled"
            );
        }

        if (name.length() < 2 || name.length() > 120) {
            throw new IllegalStateException(
                    "BOOTSTRAP_ADMIN_NAME must contain between 2 and 120 characters"
            );
        }

        if (password.length() < 12 || password.length() > 128) {
            throw new IllegalStateException(
                    "BOOTSTRAP_ADMIN_PASSWORD must contain between 12 and 128 characters"
            );
        }
    }
}
