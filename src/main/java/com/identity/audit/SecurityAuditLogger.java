package com.identity.audit;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.Locale;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class SecurityAuditLogger {

    private static final Logger log =
            LoggerFactory.getLogger(SecurityAuditLogger.class);

    public void success(String event, String actorId) {
        log.info(
                "security_audit event={} outcome=SUCCESS actorId={}",
                event,
                safeReference(actorId)
        );
    }

    public void failure(
            String event,
            String subjectReference,
            String reason
    ) {
        log.warn(
                "security_audit event={} outcome=FAILURE subjectRef={} reason={}",
                event,
                safeReference(subjectReference),
                reason
        );
    }

    public void denied(
            String event,
            String subjectReference,
            String reason
    ) {
        log.warn(
                "security_audit event={} outcome=DENIED subjectRef={} reason={}",
                event,
                safeReference(subjectReference),
                reason
        );
    }

    public String fingerprint(String value) {
        String normalized = value == null
                ? ""
                : value.trim().toLowerCase(Locale.ROOT);

        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");

            return "sha256:" + HexFormat.of().formatHex(
                    digest.digest(
                            normalized.getBytes(StandardCharsets.UTF_8)
                    )
            );
        } catch (Exception ex) {
            throw new IllegalStateException(
                    "Unable to fingerprint audit subject",
                    ex
            );
        }
    }

    private String safeReference(String value) {
        return value == null || value.isBlank()
                ? "unknown"
                : value;
    }
}
