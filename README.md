# TransIP Cert-Manager webhook

This is an implementation of a Cert-Manager webhook for implementing DNS01 acme verification with TransIP as a DNS provider.

### Installation

You can use Helm to deploy the webhook:

```shell script
$ git clone ...
$ helm install cert-manager-webhook-transip --namespace=cert-manager ./deploy/transip-webhook
```

Alternatively, you can use kubectl to deploy:

```shell script
$ kubectl -n cert-manager apply -f https://raw.githubusercontent.com/robbietjuh/cert-manager-webhook-transip/master/deploy/recommended.yaml
```

Both methods will simply deploy the webhook container into your Kubernetes environment. After deployment, you'll have to configure the webhook to interface with your TransIP account.

### Configuration

The webhook needs your TransIP account name and your API private key. The private key must be deployed as a secret.

```shell script
# Given your private key is in the file privateKey
kubectl -n cert-manager create secret generic transip-credentials --from-file=privateKey
```

After saving your private key as a secret to the cluster, you'll have to configure the Issuer object. You can use the following as a template:

```yaml
apiVersion: cert-manager.io/v1
kind: Issuer
metadata:
  name: le-staging
spec:
  acme:
    email: user@example.com
    server: https://acme-staging-v02.api.letsencrypt.org/directory
    privateKeySecretRef:
      name: le-staging-issuer-key
    solvers:
    - dns01:
        webhook:
          groupName: cert-manager.webhook.transip
          solverName: transip
          config:
            accountName: your-transip-username
            ttl: 300
            privateKeySecretRef:
              name: transip-credentials
              key: privateKey
```

That's it! Now you're set up to request your first certificate :-)

### Running the test suite

Please start out by configuring your environment in `testdata/transip/config.json`. You can then run the test suite with:

```bash
$ TEST_ZONE_NAME=example.com go test .
```
