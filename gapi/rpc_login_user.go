package gapi

import (
	"context"
	"fmt"
	db "simplebank/db/sqlc"
	"simplebank/pb"
	"simplebank/util"
	"time"

	"github.com/google/uuid"

	"google.golang.org/protobuf/types/known/timestamppb"
)

func (server *Server) CreateUser(ctx context.Context, req *pb.CreateUserRequest) (*pb.CreateUserResponse, error) {
	hashedPassword, err := util.HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to hash password: %w", err)
	}

	arg := db.CreateUserParams{
		Username:       req.Username,
		HashedPassword: hashedPassword,
		FullName:       req.FullName,
		Email:          req.Email,
	}

	user, err := server.store.CreateUser(ctx, arg)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	rsp := &pb.CreateUserResponse{
		User: convertUser(user),
	}
	return rsp, nil
}

func (server *Server) LoginUser(ctx context.Context, req *pb.LoginUserRequest) (*pb.LoginUserResponse, error) {
	user, err := server.store.GetUser(ctx, req.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	err = util.CheckPassword(req.Password, user.HashedPassword)
	if err != nil {
		return nil, fmt.Errorf("invalid password: %w", err)
	}

	accessToken, _, err := server.tokenMaker.CreateToken(user.Username, server.config.AccessTokenDuration)
	if err != nil {
		return nil, fmt.Errorf("failed to create access token: %w", err)
	}

	refreshToken, _, err := server.tokenMaker.CreateToken(user.Username, server.config.RefreshTokenDuration)
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token: %w", err)
	}

	session, err := server.store.CreateSession(ctx, db.CreateSessionParams{
		ID:           uuid.New(),
		Username:     user.Username,
		RefreshToken: refreshToken,
		UserAgent:    "grpc",
		ClientIp:     "0.0.0.0",
		IsBlocked:    false,
		ExpiresAt:    time.Now().Add(server.config.RefreshTokenDuration),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	rsp := &pb.LoginUserResponse{
		SessionId:             session.ID.String(),
		AccessToken:           accessToken,
		AccessTokenExpiresAt:  timestamppb.New(session.ExpiresAt),
		RefreshToken:          refreshToken,
		RefreshTokenExpiresAt: timestamppb.New(session.ExpiresAt),
		User:                  convertUser(user),
	}
	return rsp, nil
}

func convertUser(user db.User) *pb.User {
	return &pb.User{
		Username:          user.Username,
		FullName:          user.FullName,
		Email:             user.Email,
		PasswordChangedAt: timestamppb.New(user.PasswordChangedAt),
		CreatedAt:         timestamppb.New(user.CreatedAt),
	}
}

