-- +goose Up
ALTER TABLE users
ADD is_chirpy_red BOOL DEFAULT false;

-- +goose Down
ALTER TABLE users
DROP TABLE is_chirpy_red;