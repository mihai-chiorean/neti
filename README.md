[![codecov](https://codecov.io/gh/mihai-chiorean/neti/branch/main/graph/badge.svg?token=QCDQGK7GEX)](https://codecov.io/gh/mihai-chiorean/neti)

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
go run cli/main.go
```

which will open an http server on port 8085

4. In a separate terminal

```
curl -X POST localhost:8085 -H "Content-Type: application/json" -H "X-Mirror-Body: true" -d '{"productId": 123456, "quantity": 100}'
```

`X-Mirror-Body: true` makes the dummy server return the body of the request as the response.

# Overall architecture

https://whimsical.com/overall-arch-4Kke4cpqMq4zTubQdR82w4

![overall arch@2x](https://user-images.githubusercontent.com/2073397/133947793-b12799c6-a489-4a33-89ae-bd39b4740054.png)

## What is a "bastion" server?

https://en.wikipedia.org/wiki/Bastion_host

### tl;dr

> a server that is exposed to the internet and is used to access other servers in the private network.

In our case, the bastian is `sshd` listening on a known port.

# DNS Server

To reduce configuration friction, we want services to not have to have separate local configuraitons in their own repo for routing. To use the same configuraiton as prod, we need to understand the DNSs mapped inside the k8s cluster. One of the main challenges here is doing this mapping on local `/etc/hosts` is too much friction. However, if we can edit `/etc/hosts` one time and add an entry that points to a fake DNS server that we run, then we have control over this routing and can map the service DNSs on the fly.

# Structure

## Gateway

The bastion is `sshd`, which is exposed to the internet and is used to access the gateway server. We open an SSH connection - including the relevant auth - to the ssh server on 8023.
Once we have the handshake completed, we run a command that starts a gateway process. Once the gateway process is started, we can start sending commands to it via the ssh connection - basically we have a subchannel that connects to it.
Then we use the API to open HTTP proxies.

The benefits of this architecture:

- separate gateway process for each user connecting.
- while working on the cli, every time the cli is started, it's paired with a new gateway process, in stead of the gw "dying" when the cli is closed.

### Open question:

- do we need a subchannel for each http proxy though both the bastion and the gateway to properly multiplex? Or is this happening already?

### api/

This package holds the "communication protocol" between the client and the gateway. It defines methods used via the ssh protocol for the client to ask the gateway to do
some operations (like opening a proxy).

Implemented so far:

1. Handshake
2. NewHTTPProxy

#### `Handshake`

Currently it only opens a tcp port that it respons with. Once the client connects to it, the gateway is going to start sending logs to this port
for the client to display.

#### `NewHTTPProxy`

Lazily initializes an http proxy on the gateway side.


## Command line

```
A longer description that spans multiple lines and likely contains
examples and usage of using your application. For example:

Cobra is a CLI library for Go that empowers applications.
This application is a tool to generate the needed files
to quickly create a Cobra application.

Usage:
  cli [flags]

Flags:
  -c, --config string    config file (default is .cli.yaml) (default ".cli.yaml")
  -g, --gateway string   gateway hostport
  -h, --help             help for cli
  -k, --key string       private key file
  -p, --port string      port for http proxy to listen on (default "8085")
  -t, --toggle           Help message for toggle
```

# Useful links

- https://istio.io/latest/docs/tasks/traffic-management/request-routing/


# TODO:

## 1. Docs on how to run and test

