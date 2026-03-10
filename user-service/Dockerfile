FROM golang:1.22-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o user-service .

FROM alpine:3.20

WORKDIR /app

COPY --from=builder /app/user-service /app/user-service

RUN adduser -D -H appuser && \
    chown appuser:appuser /app/user-service && \
    apk add --no-cache ca-certificates wget

USER appuser

EXPOSE 8080

ENTRYPOINT ["/app/user-service"]

