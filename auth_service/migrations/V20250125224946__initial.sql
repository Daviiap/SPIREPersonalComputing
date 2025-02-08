-- Migration file created on 20250125224946
CREATE SCHEMA IF NOT EXISTS users;

COMMENT ON SCHEMA users IS 'Schema to treat users';

CREATE TABLE users.User (
    "id" UUID PRIMARY KEY,
    "name" VARCHAR(255) UNIQUE NOT NULL,
    "email" VARCHAR(255) UNIQUE NOT NULL,
    "organization" VARCHAR(255),
    "password" TEXT NOT NULL,
    "created_at" TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_user_name ON users.User(name);

CREATE INDEX IF NOT EXISTS idx_user_email ON users.User(email);