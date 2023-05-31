FROM golang:latest as gateway 

# Update and install packages
RUN apt-get update && \
    apt-get install -y openssh-server

# Create SSH user and set password (replace 'your_password' with a secure password)
RUN useradd -m testuser && \
    echo "testuser:tiger" | chpasswd

# Configure SSH
RUN mkdir /var/run/sshd && \
    echo 'Port 8023' >> /etc/ssh/sshd_config && \
    echo 'PermitRootLogin no' >> /etc/ssh/sshd_config && \
    echo 'PasswordAuthentication yes' >> /etc/ssh/sshd_config && \
    echo 'AllowTcpForwarding yes' >> /etc/ssh/sshd_config && \
    echo 'PermitTunnel yes' >> /etc/ssh/sshd_config && \
    echo 'PermitTTY no' >> /etc/ssh/sshd_config && \
    echo 'Match User testuser' >> /etc/ssh/sshd_config 
# && \
# echo '    ForceCommand /bin/gateway' >> /etc/ssh/sshd_config



# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
# COPY go.mod go.sum ./

# Copy the source from the current directory to the Working Directory inside the container
COPY ./ ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Build the Go app
RUN go build -o /bin/gateway ./gateway

# Expose port 8080 to the outside world
EXPOSE 22

# Expose SSH port
EXPOSE 8022
EXPOSE 8023

# Command to run the executable
# CMD ["/bin/gateway"]

# Start SSH server
CMD ["/usr/sbin/sshd", "-D"]