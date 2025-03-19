package gapi

import (
	"context"
	"log"
	"net/http"
	"time"

	"google.golang.org/grpc"
)

func GrpcLogger(
	ctx context.Context,
	req interface{},
	info *grpc.UnaryServerInfo,
	handler grpc.UnaryHandler,
) (resp interface{}, err error) {
	
	
	result, err := handler(ctx, req)
	if err != nil {
		log.Printf("error: %v", err)
	} else {
		log.Printf("success: %v", result)
	}
	return result, err
}

func HttpLogger(
	handler http.Handler,
) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		handler.ServeHTTP(w, r)
		log.Printf("request completed: %s in %v", r.URL.Path, time.Since(start))
	})
}