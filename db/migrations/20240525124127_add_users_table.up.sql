CREATE TABLE "users" (
  "id_user" SERIAL PRIMARY KEY,
  "username" varchar NOT NULL,
  "password" varchar NOT NULL,
  "salt" varchar not null,
  "email" varchar NOT NULL,
  "role" varchar NOT NULL,
  "created_at" timestamp DEFAULT (CURRENT_TIMESTAMP),
  "updated_at" timestamp
);

