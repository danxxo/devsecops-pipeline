FROM golang:1.25 AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -o server ./cmd/server

FROM alpine:3.23

WORKDIR /app

COPY --from=builder /app/server .

RUN addgroup -g 1500 appuser && adduser -D -u 1500 -G appuser appuser \
    && chown -R appuser:appuser /app

EXPOSE 9100

USER appuser

CMD ["./server"]
