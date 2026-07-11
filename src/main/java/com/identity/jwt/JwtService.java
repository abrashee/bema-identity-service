package com.identity.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Date;
import java.util.Map;
import java.util.Objects;
import java.util.UUID;

@Service
public class JwtService {

    private final SecretKey key;
    private final long expirationMs;

    public JwtService(
            @Value("${security.jwt.secret}") String secret,
            @Value("${security.jwt.expiration}") long expirationMs
    ) {
        if (secret == null || secret.trim().length() < 32) {
            throw new IllegalStateException("JWT secret must be at least 32 characters long");
        }
        if (expirationMs <= 0) {
            throw new IllegalStateException("JWT expiration must be positive");
        }

        this.key = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.expirationMs = expirationMs;
    }

    public String generateToken(String userId) {
        return generateToken(userId, Map.of(), expirationMs);
    }

    public String generateInternalServiceToken(String serviceName) {
        return generateToken(
                serviceName,
                Map.of("scope", "internal"),
                Math.min(expirationMs, 300_000L)
        );
    }

    public String generateToken(
            String subject,
            Map<String, Object> claims,
            long ttlMs
    ) {
        Objects.requireNonNull(subject, "subject");

        Instant issuedAt = Instant.now();
        Instant expiresAt = issuedAt.plusMillis(ttlMs);

        return Jwts.builder()
                .setId(UUID.randomUUID().toString())
                .setSubject(subject)
                .addClaims(claims)
                .setIssuedAt(Date.from(issuedAt))
                .setExpiration(Date.from(expiresAt))
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();
    }

    public String extractUserId(String token) {
        return parseClaims(token).getSubject();
    }

    public AccessTokenMetadata extractAccessTokenMetadata(String token) {
        Claims claims = parseClaims(token);

        return new AccessTokenMetadata(
                claims.getId(),
                claims.getSubject(),
                claims.getExpiration().toInstant()
        );
    }

    private Claims parseClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public record AccessTokenMetadata(
            String tokenId,
            String subject,
            Instant expiresAt
    ) {}
}
