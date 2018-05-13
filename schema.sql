CREATE TABLE tokens (
    token_id       CHARACTER(64)                                    NOT NULL PRIMARY KEY,
    token_hash     CHARACTER VARYING(255)                           NOT NULL,
    auth_me        CHARACTER VARYING(255)                           NOT NULL,
    auth_client_id CHARACTER VARYING(255)                           NOT NULL,
    auth_scope     CHARACTER VARYING(255)                           NOT NULL,
    created        TIMESTAMP              DEFAULT CURRENT_TIMESTAMP NOT NULL,
    revoked        TIMESTAMP              DEFAULT NULL
);
CREATE TABLE settings (
    setting_name   CHARACTER VARYING(255) NOT NULL,
    setting_value  CHARACTER VARYING(255) NOT NULL,
    CONSTRAINT setting UNIQUE (setting_name, setting_value)
);
