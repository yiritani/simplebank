-- name: UpdateUserPassword :exec
UPDATE users
SET
  hashed_password = $1,
  password_changed_at = NOW()
WHERE
  username = $2; 