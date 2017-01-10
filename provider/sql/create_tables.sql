CREATE TABLE IF NOT EXISTS Users
( id                INT PRIMARY KEY
, email             TEXT
, password          TEXT INT NOT NULL
, name              TEXT
, memo              TEXT
);

CREATE TABLE IF NOT EXISTS Client
( client_id         CHAR(100) UNIQUE
, user              INT
, grant_type        CHAR(18) DEFAULT "authorization_code"
, response_type     CHAR(4) DEFAULT "code"
, scopes            TEXT
, default_scopes    TEXT
, redirect_uris     TEXT
, default_redirect_uri TEXT
, CONSTRAINT fk_C_user FOREIGN KEY (`user`) references `Users`(`id`)
);

CREATE TABLE IF NOT EXISTS BearerToken
( client_id         CHAR(100) UNIQUE
, user              INT
, scopes            TEXT
, access_token      CHAR(100)
, refresh_token     CHAR(100)
, expiration_time   INT DEFAULT (strftime("%s","now") + 3600)
, CONSTRAINT fk_BT_client FOREIGN KEY (`client_id`) references `Client`(`client_id`)
, CONSTRAINT fk_BT_user FOREIGN KEY (`user`) references `Users`(`id`)
);

CREATE TABLE IF NOT EXISTS AuthorizationCode
( client_id         CHAR(100) UNIQUE
, user              INT
, scopes            TEXT
, code              CHAR(100)
, expiration_time   INT DEFAULT (strftime("%s","now") + 600)
, CONSTRAINT fk_AC_client FOREIGN KEY (`client_id`) references `Client`(`client_id`)
, CONSTRAINT fk_AC_user FOREIGN KEY (`user`) references `Users`(`id`)
);