-- name: CreateUser :one
INSERT INTO users (id, created_at, updated_at, email, hashed_password)
VALUES (
    gen_random_uuid(),
    NOW(),
    NOW(),
    $1,
    $2
) RETURNING id, created_at, updated_at, email, is_chirpy_red;

-- name: DeleteAllUsers :exec
DELETE FROM users;

-- name: GetUserByEmail :one
SELECT * from users WHERE email = $1;

-- name: UpdateUser :one
UPDATE users 
SET updated_at = NOW(),
email = $2,
hashed_password = $3
WHERE id = $1
RETURNING id, created_at, updated_at, email, is_chirpy_red;

-- name: MakeUserChirpyRed :exec
UPDATE users
SET is_chirpy_red = true,
updated_at = NOW()
WHERE id = $1;