FROM golang:1.25-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY go.mod ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o post-service .

FROM alpine:3.20

WORKDIR /app

COPY --from=builder /app/post-service /app/post-service

RUN adduser -D -H appuser && \
    chown appuser:appuser /app/post-service && \
    apk add --no-cache ca-certificates wget

USER appuser

EXPOSE 8585

ENTRYPOINT ["/app/post-service"]

