package com.identity.security;

import com.identity.audit.SecurityAuditLogger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.Locale;

@Service
public class LoginBruteForceProtectionService {

    private static final String FAILURE_KEY_PREFIX = "auth:login-failures:";
    private static final String LOCK_KEY_PREFIX = "auth:login-lock:";

    private final StringRedisTemplate redisTemplate;
    private final int maxFailures;
    private final Duration failureWindow;
    private final Duration lockDuration;
    private final SecurityAuditLogger auditLogger;

    public LoginBruteForceProtectionService(
            StringRedisTemplate redisTemplate,
            @Value("${security.brute-force.max-failures:5}") int maxFailures,
            @Value("${security.brute-force.failure-window-seconds:900}") long failureWindowSeconds,
            @Value("${security.brute-force.lock-seconds:900}") long lockSeconds,
            SecurityAuditLogger auditLogger
    ) {
        if (maxFailures <= 0) {
            throw new IllegalStateException("Brute-force max failures must be positive");
        }
        if (failureWindowSeconds <= 0 || lockSeconds <= 0) {
            throw new IllegalStateException("Brute-force durations must be positive");
        }

        this.redisTemplate = redisTemplate;
        this.maxFailures = maxFailures;
        this.failureWindow = Duration.ofSeconds(failureWindowSeconds);
        this.lockDuration = Duration.ofSeconds(lockSeconds);
        this.auditLogger = auditLogger;
    }

    public boolean isLocked(String email) {
        return Boolean.TRUE.equals(
                redisTemplate.hasKey(lockKey(normalize(email)))
        );
    }

    public void recordFailure(String email) {
        String normalizedEmail = normalize(email);
        String failureKey = failureKey(normalizedEmail);

        Long failures = redisTemplate.opsForValue().increment(failureKey);

        if (failures != null && failures == 1L) {
            redisTemplate.expire(failureKey, failureWindow);
        }

        if (failures != null && failures >= maxFailures) {
            redisTemplate.opsForValue().set(
                    lockKey(normalizedEmail),
                    "locked",
                    lockDuration
            );
            redisTemplate.delete(failureKey);
            auditLogger.denied(
                    "AUTH_ACCOUNT_LOCK",
                    auditLogger.fingerprint(normalizedEmail),
                    "FAILURE_THRESHOLD_REACHED"
            );
        }
    }

    public void recordSuccess(String email) {
        String normalizedEmail = normalize(email);
        redisTemplate.delete(failureKey(normalizedEmail));
        redisTemplate.delete(lockKey(normalizedEmail));
    }

    private String normalize(String email) {
        return email == null
                ? ""
                : email.trim().toLowerCase(Locale.ROOT);
    }

    private String failureKey(String normalizedEmail) {
        return FAILURE_KEY_PREFIX + normalizedEmail;
    }

    private String lockKey(String normalizedEmail) {
        return LOCK_KEY_PREFIX + normalizedEmail;
    }
}
