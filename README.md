# Name

https://en.wikipedia.org/wiki/Neti_(deity)

# How to run

1. You'll need to create an unencripted RSA private key `private-unencrypted.pem` that will be used by the ssh tunnel to the docker container to create `known_hosts` 

2. 
```
docker-compose up --build
```
will build and start the gateway in a docker container

3. In a separate terminal
```
go run internal/proxy/proxy.go
```
which will open an http server on port 8085

4. In another terminal `curl localhost:8085` will respond with "hello world"

