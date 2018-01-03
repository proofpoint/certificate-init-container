[![Latest Release](http://github-release-version.herokuapp.com/github/proofpoint/certificate-init-container/release.svg)](https://github.com/proofpoint/certificate-init-container/releases/latest)
[![Latest Docker Tag](https://images.microbadger.com/badges/version/proofpoint/certificate-init-container.svg)](https://microbadger.com/images/proofpoint/certificate-init-container "Get your own version badge on microbadger.com")
[![Latest Docker Tag Details](https://images.microbadger.com/badges/image/proofpoint/certificate-init-container.svg)](https://microbadger.com/images/proofpoint/certificate-init-container "Get your own image badge on microbadger.com")

# Certificate Init Container

The `certificate-init-container` generates TLS certificates for pods using the
[Kubernetes certificate API](https://kubernetes.io/docs/tasks/tls/managing-tls-in-a-cluster).

## Prerequisites

* Kubernetes 1.6.0+

## Usage

Create a deployment that uses the `certificate-init-container`:

```
kubectl create -f deployments/tls-app.yaml
```

The `certificate-init-container` will generate a private key, certificate
signing request (csr), and submit a certificate signing request to the
Kubernetes certificate API, then wait for the certificate to be approved.

For handling approval of certificate requests we recommend using
[proofpoint/kapprover](https://github.com/proofpoint/kapprover).

Once the certificate signing request has been approved the
`certificate-init-container` will fetch the signed certificate and write it in
both PEM and Java keystore (password "keystore") format to a shared filesystem.

Next the `certificate-init-container` will exit and the pod will start the
remaining containers, which will have access to the certificate and private key.

See the [example deployment](deployments/tls-app.yaml) for more details.
