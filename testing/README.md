# Testing

A guide on how to set up and test the Neti gateway in k8s environments and a mirror service with an HTTP API called "dummy".

## Host key

The connection to the cluster involves an ssh handshake. As part of it, a host key is needed to prevent man-in-the-middle attacks.

Create a key:

```
ssh-keygen -t rsa -b 4096 -C "..."
```

## EKS

```
$ ./testing/create-eks-cluster
```

```
$ eksctl utils write-kubeconfig --cluster neti-testing
```
## MiniKube

## Kubernetes

```
$ kubectl create namespace neti-testing
```

Setup host key secret
```
$ kubectl create secret generic probe-key --from-file=<path to id_rsa you created> -n neti-testing
```

### EKS

```
$ kubectl apply -f neti-gw-deployment.yaml
```
Note: Check the configuration to see how the key is used.