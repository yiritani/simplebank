package gapi

import (
	"context"
	"strings"

	"simplebank/token"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	authorizationHeaderKey  = "authorization"
	authorizationBearerPrefix = "Bearer"
)

func (server *Server) authorizeUser(ctx context.Context) (*token.Payload, error) {
	md, ok := metadata.FromIncomingContext(ctx)
	if !ok {
		return nil, status.Errorf(codes.Unauthenticated, "metadata is not provided")
	}

	values := md.Get(authorizationHeaderKey)
	if len(values) == 0 {
		return nil, status.Errorf(codes.Unauthenticated, "authorization token is not provided")
	}

	authHeader := values[0]
	fields := strings.Fields(authHeader)
	if len(fields) < 2 {
		return nil, status.Errorf(codes.Unauthenticated, "authorization token must be in the format 'Bearer {token}'")
	}

	authType := fields[0]
	if authType != authorizationBearerPrefix {
		return nil, status.Errorf(codes.Unauthenticated, "authorization token must start with '%s'", authorizationBearerPrefix)
	}

	accessToken := fields[1]
	payload, err := server.tokenMaker.VerifyToken(accessToken)
	if err != nil {
		return nil, status.Errorf(codes.Unauthenticated, "invalid authorization token: %v", err)
	}

	return payload, nil
}