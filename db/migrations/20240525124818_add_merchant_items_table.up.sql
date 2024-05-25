CREATE TABLE "merchant_items" (
  "id_merchant_item" SERIAL PRIMARY KEY,
  "name" varchar NOT NULL,
  "product_category" varchar NOT NULL,
  "price" decimal NOT NULL,
  "image_url" text NOT NULL,
  "created_at" timestamp DEFAULT (CURRENT_TIMESTAMP),
  "updated_at" timestamp
);
