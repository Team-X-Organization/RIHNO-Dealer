FROM golang:latest

# Install git and bash for easier dev work
RUN apk add --no-cache git bash

WORKDIR /app

# Copy modules first to save time on rebuilds
COPY go.mod go.sum ./
RUN go mod download

# Copy everything else
COPY . .

# Expose the socket port
EXPOSE 8080

# Run the app directly using 'go run' for development
# This allows you to restart the container to pick up changes quickly
CMD ["go", "run", "main.go"]