# Build stage
FROM golang:1.23-alpine3.19 AS builder
WORKDIR /app
COPY . .
RUN go build -o main main.go

# Run stage
FROM alpine:3.19
WORKDIR /app
COPY --from=builder /app/main .
COPY app.env .
COPY start.sh .
COPY wait-for.sh .
COPY db/migration ./db/migration

# Add execute permission to scripts
RUN chmod +x start.sh wait-for.sh

EXPOSE 8080 9090
CMD [ "/app/main" ]
ENTRYPOINT [ "/app/start.sh" ]
