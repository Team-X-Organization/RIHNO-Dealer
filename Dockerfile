FROM golang:latest

# Use apt-get instead of apk for standard Debian-based images
RUN apt-get update && apt-get install -y git bash && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy modules
COPY go.mod go.sum ./
RUN go mod download

# Copy everything else
COPY . .

EXPOSE 8080

CMD ["go", "run", "main.go"]