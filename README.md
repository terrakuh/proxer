# Proxer

## Creating self signed certificate and key

```shell
openssl ecparam -genkey -name secp384r1 > ca.key
openssl req -new -x509 -days $((5*365)) -key ca.key -out ca.crt
```
