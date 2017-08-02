# nexus-google-iam-proxy
A proxy for authenticating Nexus Repository Manager OSS users against Google Cloud IAM.

## Pre-requisites

* JDK 8.
* A GCP organization.
* A GCP project with the _Cloud Resources Manager_ API enabled.
* A set of credentials of type _OAuth Client ID_ obtained from _GCP > API Manager > Credentials_.
* Proper configuration of the resulting client with respect to the redirect URL.
* A running and properly configured instance of Nexus.

## Generating the Keystore

The following command will generate a suitable keystore for signing JWTs:

```bash
$ keytool -genkey \
          -keystore keystore.jceks \
          -storetype jceks \
          -keyalg RSA \
          -keysize 2048 \
          -alias RS256 \
          -sigalg SHA256withRSA \
          -dname "CN=,OU=,O=,L=,ST=,C=" \
          -validity 3651
```

You will be prompted for two passwords. Please make sure they are the same. Feel free to change the value of the `dname`, `keystore` and `validity` parameters.

## Building

The following command will build the project and generate a runnable jar:

```bash
$ ./gradlew build
```

## Running

The following command will run the proxy on port `8080` pointing to a local
Nexus instance:

```bash
$ ALLOWED_USER_AGENTS_ON_ROOT_REGEX="GoogleHC" \
  AUTH_CACHE_TTL="60000" \
  BIND_PORT="8080" \
  CLIENT_ID="my-client-id" \
  CLIENT_SECRET="my-client-secret" \
  KEYSTORE_PATH="./.secrets/keystore.jceks" \
  KEYSTORE_PASS="my-keystore-password" \
  NEXUS_DOCKER_HOST="containers.example.com" \
  NEXUS_HTTP_HOST="nexus.example.com" \
  NEXUS_RUT_HEADER="X-Forwarded-User" \
  ORGANIZATION_ID="123412341234" \
  REDIRECT_URL="https://nexus.example.com/oauth/callback" \
  SESSION_TTL="1440000" \
  TLS_ENABLED="false" \
  UPSTREAM_DOCKER_PORT="5000" \
  UPSTREAM_HTTP_PORT="8081" \
  UPSTREAM_HOST="localhost" \
  java -jar ./build/libs/nexus-proxy.jar
```

Please check below for a description of all the supported environment variables.

## Environment Variables

| Name                                | Description |
|-------------------------------------|-------------|
| `ALLOWED_USER_AGENTS_ON_ROOT_REGEX` | A regex against which to match the `User-Agent` of requests to `GET /` so that they can be answered with `200 OK`. |
| `AUTH_CACHE_TTL`                    | The amount of time (in _milliseconds_) during which to cache the fact that a given user is authorized to make requests. |
| `BIND_PORT`                         | The port on which to listen for incoming requests. |
| `CLIENT_ID`                         | The application's client ID in _GCP / API Manager / Credentials_. |
| `CLIENT_SECRET`                     | The abovementioned application's client secret. |
| `KEYSTORE_PATH`                     | The path to the keystore containing the key with which to sign JWTs. |
| `KEYSTORE_PASS`                     | The password of the abovementioned keystore. |
| `NEXUS_DOCKER_HOST`                 | The host used to access the Nexus Docker registry. |
| `NEXUS_HTTP_HOST`                   | The host used to access the Nexus UI and Maven repositories. |
| `NEXUS_RUT_HEADER`                  | The name of the header which will convey auth info to Nexus. |
| `ORGANIZATION_ID`                   | The ID of the organization against which to validate users' membership. |
| `REDIRECT_URL`                      | The URL where to redirect users after the OAuth2 consent screen. |
| `SESSION_TTL`                       | The TTL (in _milliseconds_) of a user's session. |
| `TLS_CERT_PK12_PATH`                | The path to the PK12 file to use when enabling TLS. |
| `TLS_CERT_PK12_PASS`                | The password of the PK12 file to use when enabling TLS. |
| `TLS_ENABLED`                       | Whether to enable TLS. |
| `UPSTREAM_DOCKER_PORT`              | The port where the proxied Nexus Docker registry listens. |
| `UPSTREAM_HTTP_PORT`                | The port where the proxied Nexus instance listens. |
| `UPSTREAM_HOST`                     | The host where the proxied Nexus instance listens. |
