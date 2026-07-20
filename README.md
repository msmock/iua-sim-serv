# IUA Simulation Server

## JWT token signature algorithm:

https://auth0.com/blog/json-web-token-signing-algorithms-overview/

The client simulator supports the required and recommended algorithm:
* HMAC + SHA256
* RSASSA-PKCS1-v1_5 + SHA256
* ECDSA + P-256 + SHA256

## RSA key generation

https://stackoverflow.com/questions/11410770/load-rsa-public-key-from-file

- Generate a 2048-bit RSA private key: `openssl genrsa -out private_key.pem 2048`
- Convert private Key to PKCS#8 format (so Java can read it): `openssl pkcs8 -topk8 -inform PEM -outform DER -in private_key.pem -out private_key.der -nocrypt`
- Output public key portion in DER format (so Java can read it): `openssl rsa -in private_key.pem -pubout -outform DER -out public_key.der`

## ES256 key generation

- `openssl ecparam -name prime256v1 -genkey -noout -out private-key.pem`
- `openssl ec -in private-key.pem -pubout -out public-key.pem`

The private key will be saved in private-key.pem and the public key will be saved in public-key.pem.

# JWT encoding 

JWTs are encoded by taking three parts: the header, payload, and signature. Each part is Base64Url encoded and then 
concatenated with periods ('.') to form the final JWT string. 

First part declares the algorithm in a JSON, e.g.:
````
{"alg": "HS256", "typ": "JWT"}
````

Values may be: 
- HS256 : HMAC with SHA-256
- RS256	: RSA Signature with SHA-256
- ES256	: ECDSA Signature with P-256

## Running the application in dev mode

You can run your application in dev mode that enables live coding using:

```shell script
./mvnw quarkus:dev
```

> **_NOTE:_**  Quarkus ships with a Dev UI, which is available in dev mode only at <http://localhost:8080/q/dev/>.

## Creating a native executable

You can run the native executable build in a container using:

```shell script
./mvnw package -Dnative -Dquarkus.native.container-build=true
```

You can then execute your native executable with: `./target/quarkus-test-1.0.0-SNAPSHOT-runner`

## Create docker image

```shell script
docker build -t iua-ru-serv .
```
