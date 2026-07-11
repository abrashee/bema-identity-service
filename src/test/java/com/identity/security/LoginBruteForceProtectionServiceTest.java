package com.identity.security;

import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.*;

class LoginBruteForceProtectionServiceTest {

    @Test
    void locksAccountAfterMaximumFailures() {
        StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);

        @SuppressWarnings("unchecked")
        ValueOperations<String, String> valueOperations =
                mock(ValueOperations.class);

        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
        when(valueOperations.increment("auth:login-failures:user@example.com"))
                .thenReturn(1L, 2L, 3L);

        LoginBruteForceProtectionService service =
                new LoginBruteForceProtectionService(
                        redisTemplate,
                        3,
                        900,
                        900
                );

        service.recordFailure(" User@Example.com ");
        service.recordFailure("user@example.com");
        service.recordFailure("user@example.com");

        verify(redisTemplate).expire(
                "auth:login-failures:user@example.com",
                Duration.ofSeconds(900)
        );

        verify(valueOperations).set(
                "auth:login-lock:user@example.com",
                "locked",
                Duration.ofSeconds(900)
        );

        verify(redisTemplate).delete(
                "auth:login-failures:user@example.com"
        );
    }

    @Test
    void reportsLockedAccountFromRedis() {
        StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);

        when(redisTemplate.hasKey("auth:login-lock:user@example.com"))
                .thenReturn(true);

        LoginBruteForceProtectionService service =
                new LoginBruteForceProtectionService(
                        redisTemplate,
                        5,
                        900,
                        900
                );

        assertTrue(service.isLocked(" USER@EXAMPLE.COM "));
    }

    @Test
    void reportsUnlockedAccountWhenLockKeyIsAbsent() {
        StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);

        when(redisTemplate.hasKey("auth:login-lock:user@example.com"))
                .thenReturn(false);

        LoginBruteForceProtectionService service =
                new LoginBruteForceProtectionService(
                        redisTemplate,
                        5,
                        900,
                        900
                );

        assertFalse(service.isLocked("user@example.com"));
    }

    @Test
    void successfulLoginClearsFailureAndLockKeys() {
        StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);

        LoginBruteForceProtectionService service =
                new LoginBruteForceProtectionService(
                        redisTemplate,
                        5,
                        900,
                        900
                );

        service.recordSuccess(" User@Example.com ");

        verify(redisTemplate).delete(
                "auth:login-failures:user@example.com"
        );
        verify(redisTemplate).delete(
                "auth:login-lock:user@example.com"
        );
    }
}
