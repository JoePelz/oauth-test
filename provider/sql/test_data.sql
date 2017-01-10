INSERT INTO Users (email, password, name, memo) VALUES ("A@B.com", "12345", "Kim", "Personal Data");
INSERT INTO Users (email, password, name, memo) VALUES ("test@example.ru", "abcdefg", "Petra", "Private info");
INSERT INTO Users (email, password, name, memo) VALUES ("here@there.cn", "sriracha", "Aidra", "custom notes");

INSERT INTO Client (user, scopes, redirect_uris)
  VALUES (1, "admin", "http://localhost:8080/private");