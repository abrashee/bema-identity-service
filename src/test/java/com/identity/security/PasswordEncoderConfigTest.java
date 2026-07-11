package com.identity.security;

import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PasswordEncoderConfigTest {

    @Test
    void hashesPasswordsWithBcryptAndVerifiesMatches() {
        PasswordEncoder encoder =
                new PasswordEncoderConfig().passwordEncoder();

        String rawPassword = "BemaSecurePassword123!";
        String encodedPassword = encoder.encode(rawPassword);

        assertNotEquals(rawPassword, encodedPassword);
        assertTrue(encodedPassword.startsWith("$2"));
        assertTrue(encoder.matches(rawPassword, encodedPassword));
        assertFalse(encoder.matches("WrongPassword123!", encodedPassword));
    }

    @Test
    void generatesDifferentHashesForTheSamePassword() {
        PasswordEncoder encoder =
                new PasswordEncoderConfig().passwordEncoder();

        String rawPassword = "BemaSecurePassword123!";

        String firstHash = encoder.encode(rawPassword);
        String secondHash = encoder.encode(rawPassword);

        assertNotEquals(firstHash, secondHash);
        assertTrue(encoder.matches(rawPassword, firstHash));
        assertTrue(encoder.matches(rawPassword, secondHash));
    }
}
