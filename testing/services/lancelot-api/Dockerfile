# Use the official Go image as the parent image
FROM golang:1.20.3-alpine3.17 AS build

# Set the working directory inside the container
WORKDIR /app

# Copy the Go module files to the working directory
#COPY go.mod go.sum ./

# Download the Go module dependencies
# RUN go mod download

# Copy the source code to the working directory
COPY . .

# Build the Go binary with CGO disabled
RUN CGO_ENABLED=0 go build -o /lancelot-api .

# Use a minimal image for the final image
FROM alpine:3.17

# Copy the binary from the build image
COPY --from=build /lancelot-api /lancelot-api

# Set the command to run the binary
CMD ["/lancelot-api"]

