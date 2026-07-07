package com.identity.jwt;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

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
}
