INSERT INTO Users (id, email, password, name, memo) VALUES (1, 'A@B.com', '12345', 'Kim', 'Personal Data');
INSERT INTO Users (id, email, password, name, memo) VALUES (2, 'test@example.ru', 'abcdefg', 'Petra', 'Private info');
INSERT INTO Users (id, email, password, name, memo) VALUES (3, 'here@there.cn', 'sriracha', 'Aidra', 'custom notes');
-- users 1, 2, 3

INSERT INTO Client (client_id, user, scopes, redirect_uris)
  VALUES ('0123456789abcdef', 1, 'base,admin', 'http://localhost:8080/private');

INSERT INTO BearerToken (client_id, user, scopes, access_token, refresh_token)
  VALUES ('0123456789abcdef', 2, 'admin', '123access123', '456refresh456');

INSERT INTO AuthorizationCode (client_id, user, scopes, code)
  VALUES ('0123456789abcdef', 2, 'admin', '789secretcode789');