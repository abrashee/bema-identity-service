package com.identity.security;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;

@Service
public class AccessTokenRevocationService {

    private static final String KEY_PREFIX = "auth:revoked-access-token:";

    private final StringRedisTemplate redisTemplate;

    public AccessTokenRevocationService(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public void revoke(String tokenId, Instant expiresAt) {
        if (tokenId == null || tokenId.isBlank() || expiresAt == null) {
            return;
        }

        Duration remainingLifetime = Duration.between(Instant.now(), expiresAt);

        if (remainingLifetime.isNegative() || remainingLifetime.isZero()) {
            return;
        }

        redisTemplate.opsForValue().set(
                KEY_PREFIX + tokenId,
                "revoked",
                remainingLifetime
        );
    }

    public boolean isRevoked(String tokenId) {
        return tokenId != null
                && !tokenId.isBlank()
                && Boolean.TRUE.equals(redisTemplate.hasKey(KEY_PREFIX + tokenId));
    }
}
