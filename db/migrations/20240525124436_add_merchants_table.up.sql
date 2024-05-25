CREATE TABLE "merchants" (
  "id_merchant" SERIAL PRIMARY KEY,
  "name" varchar NOT NULL,
  "merchant_category" varchar NOT NULL,
  "image_url" text NOT NULL,
  "lat" decimal NOT NULL,
  "long" decimal NOT NULL,
  "created_at" timestamp DEFAULT (CURRENT_TIMESTAMP),
  "updated_at" timestamp
);
