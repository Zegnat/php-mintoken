CREATE TABLE tokens (
    token_id       CHARACTER(64)          NOT NULL UNIQUE,
    token_hash     CHARACTER VARYING(255) NOT NULL,
    auth_me        CHARACTER VARYING(255) NOT NULL,
    auth_client_id CHARACTER VARYING(255) NOT NULL,
    auth_scope     CHARACTER VARYING(255) NOT NULL,
    created        TIMESTAMP              NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked        TIMESTAMP                       DEFAULT NULL,
    PRIMARY KEY (token_id)
);
CREATE TABLE settings (
    setting_name   CHARACTER VARYING(255) NOT NULL,
    setting_value  CHARACTER VARYING(255) NOT NULL,
                   CONSTRAINT setting UNIQUE (setting_name, setting_value)
);
COMMIT;
