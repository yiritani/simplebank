package gapi

import (
	"context"
	"database/sql"
	"fmt"
	db "simplebank/db/sqlc"
	"simplebank/pb"
	"simplebank/val"

	"github.com/jackc/pgx/v5/pgtype"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func (server *Server) UpdateUser(ctx context.Context, req *pb.UpdateUserRequest) (*pb.UpdateUserResponse, error) {
	authPayload, err := server.authorizeUser(ctx)
	if err != nil {
		return nil, unauthenticatedError(err)
	}

	violations := validateUpdateUserRequest(req)
	if len(violations) > 0 {
		return nil, invalidArgumentError(violations)
	}

	if authPayload.Username != req.Username {
		return nil, permissionDeniedError(fmt.Errorf("cannot update account for other users"))
	}

	arg := db.UpdateUserParams{
		Username: req.Username,
		FullName: pgtype.Text{String: "", Valid: false},
		Email:    pgtype.Text{String: "", Valid: false},
	}

	if req.FullName != nil {
		arg.FullName = pgtype.Text{String: *req.FullName, Valid: true}
	}
	if req.Email != nil {
		arg.Email = pgtype.Text{String: *req.Email, Valid: true}
	}

	user, err := server.store.UpdateUser(ctx, arg)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, status.Errorf(codes.NotFound, "user not found")
		}
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	rsp := &pb.UpdateUserResponse{
		User: convertUser(user),
	}
	return rsp, nil
}

func validateUpdateUserRequest(req *pb.UpdateUserRequest) []*errdetails.BadRequest_FieldViolation {
	var violations []*errdetails.BadRequest_FieldViolation
	if err := val.ValidateUsername(req.Username); err != nil {
		violations = append(violations, fieldViolations("username", err))
	}
	if req.Password != nil {
		if err := val.ValidatePassword(*req.Password); err != nil {
			violations = append(violations, fieldViolations("password", err))
		}
	}
	if req.FullName != nil {
		if err := val.ValidateFullName(*req.FullName); err != nil {
			violations = append(violations, fieldViolations("full_name", err))
		}
	}
	if req.Email != nil {
		if err := val.ValidateEmail(*req.Email); err != nil {
			violations = append(violations, fieldViolations("email", err))
		}
	}

	return violations
}
