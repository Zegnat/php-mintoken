CREATE TABLE tokens (
    token_id   CHARACTER(64)          NOT NULL UNIQUE,
    token_hash CHARACTER VARYING(255) NOT NULL,
    me         CHARACTER VARYING(255) NOT NULL,
    client_id  CHARACTER VARYING(255) NOT NULL,
    scope      CHARACTER VARYING(255) NOT NULL,
    created    TIMESTAMP              NOT NULL DEFAULT CURRENT_TIMESTAMP,
    revoked    TIMESTAMP                       DEFAULT NULL,
    PRIMARY KEY(token_id)
);
CREATE TABLE settings (
    name  CHARACTER VARYING(255) NOT NULL,
    value CHARACTER VARYING(255) NOT NULL,
          CONSTRAINT setting UNIQUE(name, value)
);
COMMIT;
