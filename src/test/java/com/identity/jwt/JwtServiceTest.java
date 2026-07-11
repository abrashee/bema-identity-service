package com.identity.jwt;

import io.jsonwebtoken.ExpiredJwtException;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JwtServiceTest {

    @Test
    void generatesAndParsesUserToken() {
        JwtService jwtService = new JwtService("a".repeat(32), 3600000L);

        String token = jwtService.generateToken("user-123");

        assertNotNull(token);
        assertEquals("user-123", jwtService.extractUserId(token));
    }

    @Test
    void generatesInternalServiceTokenWithInternalScope() {
        JwtService jwtService = new JwtService("b".repeat(32), 3600000L);

        String token = jwtService.generateInternalServiceToken("identity-service");

        assertEquals("identity-service", jwtService.extractUserId(token));
    }

    @Test
    void rejectsExpiredUserToken() {
        JwtService jwtService = new JwtService("c".repeat(32), 3600000L);

        String expiredToken = jwtService.generateToken(
                "user-123",
                Map.of(),
                -1000L
        );

        assertThrows(
                ExpiredJwtException.class,
                () -> jwtService.extractUserId(expiredToken)
        );
    }
}
