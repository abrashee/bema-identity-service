ALTER TABLE auth_users
    ADD COLUMN role VARCHAR(20) NOT NULL DEFAULT 'USER';

ALTER TABLE auth_users
    ADD CONSTRAINT chk_auth_users_role
    CHECK (role IN ('USER', 'ADMIN'));

CREATE INDEX idx_auth_users_role ON auth_users(role);
