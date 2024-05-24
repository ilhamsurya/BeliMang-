CREATE TABLE "users" (
  "id_user" integer PRIMARY KEY,
  "username" varchar NOT NULL,
  "password" varchar NOT NULL,
  "email" varchar NOT NULL,
  "role" varchar NOT NULL,
  "created_at" timestamp DEFAULT (CURRENT_TIMESTAMP),
  "updated_at" timestamp
);

CREATE TABLE "merchants" (
  "id_merchant" integer PRIMARY KEY,
  "name" varchar NOT NULL,
  "merchant_category" varchar NOT NULL,
  "image_url" text NOT NULL,
  "lat" decimal NOT NULL,
  "long" decimal NOT NULL,
  "created_at" timestamp DEFAULT (CURRENT_TIMESTAMP),
  "updated_at" timestamp
);

CREATE TABLE "merchant_items" (
  "id_merchant_item" integer PRIMARY KEY,
  "name" varchar NOT NULL,
  "product_category" varchar NOT NULL,
  "price" decimal NOT NULL,
  "image_url" text NOT NULL,
  "created_at" timestamp DEFAULT (CURRENT_TIMESTAMP),
  "updated_at" timestamp
);

CREATE TABLE "orders" (
  "id_order" integer PRIMARY KEY,
  "order_number" varchar NOT NULL,
  "id_merchant" integer,
  "id_item" integer,
  "created_at" timestamp DEFAULT (CURRENT_TIMESTAMP),
  "updated_at" timestamp
);

CREATE TABLE "user_orders" (
  "id_user" integer,
  "order_number" varchar,
  "created_at" timestamp DEFAULT (CURRENT_TIMESTAMP),
  "updated_at" timestamp
);

ALTER TABLE "orders" ADD FOREIGN KEY ("id_merchant") REFERENCES "merchants" ("id_merchant");

ALTER TABLE "orders" ADD FOREIGN KEY ("id_item") REFERENCES "merchant_items" ("id_merchant_item");

ALTER TABLE "user_orders" ADD FOREIGN KEY ("id_user") REFERENCES "users" ("id_user");

ALTER TABLE "user_orders" ADD FOREIGN KEY ("order_number") REFERENCES "orders" ("order_number");
