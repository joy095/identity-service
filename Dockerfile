FROM golang:1.24-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Build the binary from the cmd package
RUN go build -o main .

EXPOSE 8081

CMD ["./main"]
