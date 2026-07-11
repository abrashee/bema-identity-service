package com.identity.config;

import com.identity.entity.AuthUserRole;
import com.identity.jwt.JwtService;
import com.identity.repository.AuthUserRepository;
import org.junit.jupiter.api.Test;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.reactive.function.client.WebClient;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class AdminBootstrapRunnerTest {

    @Test
    void bootstrapDisabledDoesNothing() {
        AuthUserRepository repository = mock(AuthUserRepository.class);

        AdminBootstrapRunner runner = new AdminBootstrapRunner(
                false,
                "",
                "",
                "",
                repository,
                mock(PasswordEncoder.class),
                mock(JwtService.class),
                mock(WebClient.class)
        );

        runner.run(new DefaultApplicationArguments(new String[0]));

        verifyNoInteractions(repository);
    }

    @Test
    void existingAdminSkipsBootstrap() {
        AuthUserRepository repository = mock(AuthUserRepository.class);
        when(repository.existsByRole(AuthUserRole.ADMIN)).thenReturn(true);

        AdminBootstrapRunner runner = new AdminBootstrapRunner(
                true,
                "admin@example.com",
                "VerySecurePassword123!",
                "Administrator",
                repository,
                mock(PasswordEncoder.class),
                mock(JwtService.class),
                mock(WebClient.class)
        );

        runner.run(new DefaultApplicationArguments(new String[0]));

        verify(repository).existsByRole(AuthUserRole.ADMIN);
        verify(repository, never()).save(any());
    }

    @Test
    void invalidConfigurationFailsFast() {
        AdminBootstrapRunner runner = new AdminBootstrapRunner(
                true,
                "",
                "",
                "",
                mock(AuthUserRepository.class),
                mock(PasswordEncoder.class),
                mock(JwtService.class),
                mock(WebClient.class)
        );

        assertThrows(
                IllegalStateException.class,
                () -> runner.run(new DefaultApplicationArguments(new String[0]))
        );
    }
}
