CREATE TABLE IF NOT EXISTS Users
( id                INTEGER PRIMARY KEY
, email             TEXT UNIQUE
, password          TEXT INT NOT NULL
, name              TEXT
, memo              TEXT
);

CREATE TABLE IF NOT EXISTS Client
( client_id         CHAR(100) NOT NULL
, user              INTEGER NOT NULL
, grant_type        CHAR(18) DEFAULT 'authorization_code'
, response_type     CHAR(4) DEFAULT 'code'
, scopes            TEXT
, default_scopes    TEXT
, redirect_uris     TEXT
, default_redirect_uri TEXT
, CONSTRAINT pk_C_ci PRIMARY KEY (`client_id`)
, CONSTRAINT fk_C_user FOREIGN KEY (`user`) references `Users`(`id`)
);

CREATE TABLE IF NOT EXISTS BearerToken
( client_id         CHAR(100) NOT NULL UNIQUE
, user              INTEGER NOT NULL
, scopes            TEXT
, access_token      CHAR(100) NOT NULL UNIQUE
, refresh_token     CHAR(100) UNIQUE
, expiration_time   INTEGER DEFAULT ((strftime('%s','now')) + 3600)
, CONSTRAINT pk_BT_ciu PRIMARY KEY (`client_id`, `user`)
, CONSTRAINT fk_BT_client FOREIGN KEY (`client_id`) references `Client`(`client_id`)
, CONSTRAINT fk_BT_user FOREIGN KEY (`user`) references `Users`(`id`)
);

CREATE TABLE IF NOT EXISTS AuthorizationCode
( client_id         CHAR(100) UNIQUE
, code              CHAR(100) NOT NULL
, user              INTEGER NOT NULL
, scopes            TEXT
, state             TEXT
, redirect_uris     TEXT
, expiration_time   INTEGER DEFAULT (strftime('%s','now') + 600)
, CONSTRAINT pk_AC_ciu PRIMARY KEY (`client_id`, `code`)
, CONSTRAINT fk_AC_client FOREIGN KEY (`client_id`) references `Client`(`client_id`)
, CONSTRAINT fk_AC_user FOREIGN KEY (`user`) references `Users`(`id`)
);