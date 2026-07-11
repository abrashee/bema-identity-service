package com.identity.security;

import org.junit.jupiter.api.Test;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import java.time.Duration;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.startsWith;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AccessTokenRevocationServiceTest {

    @Test
    void storesRevokedTokenUntilItsExpiry() {
        StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);
        @SuppressWarnings("unchecked")
        ValueOperations<String, String> valueOperations = mock(ValueOperations.class);

        when(redisTemplate.opsForValue()).thenReturn(valueOperations);

        AccessTokenRevocationService service =
                new AccessTokenRevocationService(redisTemplate);

        service.revoke(
                "token-id-123",
                Instant.now().plusSeconds(300)
        );

        verify(valueOperations).set(
                startsWith("auth:revoked-access-token:token-id-123"),
                eq("revoked"),
                org.mockito.ArgumentMatchers.any(Duration.class)
        );
    }

    @Test
    void reportsWhetherTokenIsRevoked() {
        StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);
        AccessTokenRevocationService service =
                new AccessTokenRevocationService(redisTemplate);

        when(redisTemplate.hasKey("auth:revoked-access-token:revoked-id"))
                .thenReturn(true);
        when(redisTemplate.hasKey("auth:revoked-access-token:active-id"))
                .thenReturn(false);

        assertTrue(service.isRevoked("revoked-id"));
        assertFalse(service.isRevoked("active-id"));
    }

    @Test
    void doesNotStoreAlreadyExpiredToken() {
        StringRedisTemplate redisTemplate = mock(StringRedisTemplate.class);
        AccessTokenRevocationService service =
                new AccessTokenRevocationService(redisTemplate);

        service.revoke(
                "expired-token-id",
                Instant.now().minusSeconds(1)
        );

        verify(redisTemplate, org.mockito.Mockito.never()).opsForValue();
    }
}
