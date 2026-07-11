package com.identity.repository;

import com.identity.entity.AuthUserEntity;
import com.identity.entity.AuthUserRole;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface AuthUserRepository extends JpaRepository<AuthUserEntity, String> {

    Optional<AuthUserEntity> findByEmail(String email);

    boolean existsByRole(AuthUserRole role);
}
