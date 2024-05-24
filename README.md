# beli-mang

Project Sprint Batch 2. Project 4 : Beli Mang

## How To Run

1. Run the compose for init DB & migration in root folder
   ```bash
   docker compose up -d --build
   ```
2. Run golang inside cmd/app `go run .`

3. Migrate
   migrate -database "postgres://postgres:iatuyachie1Hae4Maih5izee1vie6Ooxu@projectsprint-db.cavsdeuj9ixh.ap-southeast-1.rds.amazonaws.com:5432/postgres?sslrootcert=ap-southeast-1-bundle.pem&sslmode=verify-full" -path db/migrations up

4. Drop
   migrate -database "postgres://postgres:iatuyachie1Hae4Maih5izee1vie6Ooxu@projectsprint-db.cavsdeuj9ixh.ap-southeast-1.rds.amazonaws.com:5432/postgres?sslrootcert=ap-southeast-1-bundle.pem&sslmode=verify-full" drop
