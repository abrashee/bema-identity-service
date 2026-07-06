package com.identity.service;

import com.identity.entity.AuthRefreshTokenEntity;
import com.identity.exception.AuthException;
import com.identity.repository.AuthRefreshTokenRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

@Service
public class RefreshTokenService {

    private static final int TOKEN_BYTES = 64;
    private static final long REFRESH_TOKEN_DAYS = 7;

    private final SecureRandom secureRandom = new SecureRandom();
    private final AuthRefreshTokenRepository repository;

    public RefreshTokenService(AuthRefreshTokenRepository repository) {
        this.repository = repository;
    }

    @Transactional
    public String issueForUser(String userId) {
        revokeActiveForUser(userId, null);

        String rawToken = generateRawToken();

        AuthRefreshTokenEntity entity = new AuthRefreshTokenEntity();
        entity.setId(UUID.randomUUID().toString());
        entity.setUserId(userId);
        entity.setTokenHash(hash(rawToken));
        entity.setCreatedAt(Instant.now());
        entity.setExpiresAt(Instant.now().plus(REFRESH_TOKEN_DAYS, ChronoUnit.DAYS));

        repository.save(entity);

        return rawToken;
    }

    @Transactional
    public String rotate(String refreshToken) {
        AuthRefreshTokenEntity current = repository.findByTokenHash(hash(refreshToken))
                .orElseThrow(() -> new AuthException("Invalid refresh token"));

        if (current.getRevokedAt() != null || current.getExpiresAt().isBefore(Instant.now())) {
            throw new AuthException("Invalid refresh token");
        }

        String newRawToken = generateRawToken();

        AuthRefreshTokenEntity replacement = new AuthRefreshTokenEntity();
        replacement.setId(UUID.randomUUID().toString());
        replacement.setUserId(current.getUserId());
        replacement.setTokenHash(hash(newRawToken));
        replacement.setCreatedAt(Instant.now());
        replacement.setExpiresAt(Instant.now().plus(REFRESH_TOKEN_DAYS, ChronoUnit.DAYS));

        repository.save(replacement);

        current.setRevokedAt(Instant.now());
        current.setReplacedByTokenId(replacement.getId());
        repository.save(current);

        return newRawToken;
    }

    @Transactional
    public String validateAndGetUserId(String refreshToken) {
        AuthRefreshTokenEntity current = repository.findByTokenHash(hash(refreshToken))
                .orElseThrow(() -> new AuthException("Invalid refresh token"));

        if (current.getRevokedAt() != null || current.getExpiresAt().isBefore(Instant.now())) {
            throw new AuthException("Invalid refresh token");
        }

        return current.getUserId();
    }

    @Transactional
    public void revoke(String refreshToken) {
        repository.findByTokenHash(hash(refreshToken)).ifPresent(token -> {
            token.setRevokedAt(Instant.now());
            repository.save(token);
        });
    }

    private void revokeActiveForUser(String userId, String replacementId) {
        for (AuthRefreshTokenEntity token : repository.findByUserIdAndRevokedAtIsNull(userId)) {
            token.setRevokedAt(Instant.now());
            token.setReplacedByTokenId(replacementId);
            repository.save(token);
        }
    }

    private String generateRawToken() {
        byte[] bytes = new byte[TOKEN_BYTES];
        secureRandom.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    private String hash(String token) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(token.getBytes(StandardCharsets.UTF_8)));
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to hash refresh token", ex);
        }
    }
}
