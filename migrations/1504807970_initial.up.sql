CREATE TABLE permissions (
       "subject" text PRIMARY KEY,
       "object" text NOT NULL,
       "verb" text NOT NULL
);

CREATE TABLE admins (
       "username" text PRIMARY KEY
);

CREATE TABLE certs (
       "client_name" text PRIMARY KEY,
       "cert_pem" text NOT NULL
);
