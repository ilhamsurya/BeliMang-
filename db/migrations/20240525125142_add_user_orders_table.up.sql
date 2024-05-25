CREATE TABLE "user_orders" (
  "id_user" integer,
  "order_number" varchar,
  "created_at" timestamp DEFAULT (CURRENT_TIMESTAMP),
  "updated_at" timestamp
);

ALTER TABLE "user_orders" ADD FOREIGN KEY ("id_user") REFERENCES "users" ("id_user");

ALTER TABLE "user_orders" ADD FOREIGN KEY ("order_number") REFERENCES "orders" ("order_number");

