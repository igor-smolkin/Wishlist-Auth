--liquibase formatted sql

--changeset ataraxii:1
CREATE TABLE users
(
    id         uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    username   varchar(32) NOT NULL UNIQUE,
    password   varchar(60) NOT NULL,
    is_enabled BOOLEAN          DEFAULT true,
    created_at timestamp        DEFAULT now()
);

CREATE TABLE roles
(
    id   SERIAL PRIMARY KEY,
    name varchar(32) NOT NULL UNIQUE
);

CREATE TABLE user_roles
(
    user_id uuid references users (id) ON DELETE CASCADE,
    role_id int references roles (id) ON DELETE CASCADE,
    PRIMARY KEY (user_id, role_id)
);

CREATE TABLE refresh_tokens
(
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token text NOT NULL,
    expiry_date timestamp NOT NULL
);

INSERT INTO roles (name)
VALUES ('USER'),
       ('ADMIN');