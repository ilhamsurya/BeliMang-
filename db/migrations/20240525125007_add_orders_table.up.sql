CREATE TABLE "orders" (
  "id_order" SERIAL PRIMARY KEY,
  "order_number" varchar unique NOT NULL,
  "id_merchant" integer,
  "id_item" integer,
  "created_at" timestamp DEFAULT (CURRENT_TIMESTAMP),
  "updated_at" timestamp
);

ALTER TABLE "orders" ADD FOREIGN KEY ("id_merchant") REFERENCES "merchants" ("id_merchant");

ALTER TABLE "orders" ADD FOREIGN KEY ("id_item") REFERENCES "merchant_items" ("id_merchant_item");
