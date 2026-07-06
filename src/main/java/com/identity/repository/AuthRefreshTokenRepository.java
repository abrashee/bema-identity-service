package com.identity.repository;

import com.identity.entity.AuthRefreshTokenEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface AuthRefreshTokenRepository extends JpaRepository<AuthRefreshTokenEntity, String> {
    Optional<AuthRefreshTokenEntity> findByTokenHash(String tokenHash);
    List<AuthRefreshTokenEntity> findByUserIdAndRevokedAtIsNull(String userId);
}
