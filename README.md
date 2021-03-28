# Name

https://en.wikipedia.org/wiki/Neti_(deity)

# How to run

1. You'll need to create an unencripted RSA private key `private-unencrypted.pem` that will be used by the ssh tunnel to the docker container to create `known_hosts` 

2. 
```
docker-compose up --build
```
will build and start the gateway in a docker container

3. 
```
ssh -o testuser@localhost -p 8022
```
Will open an ssh channel to the gateway that will reply back with what you type. The password is hardcoded as `tiger`


