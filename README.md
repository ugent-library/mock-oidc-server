# mock-oidc-server

## Build

```
go build
```

## Run

```
./mock-oid-server server
```

## Configuration

Use the following environment variables:

* `MOCK_OIDC_EXPIRES_IN`:

    * Expiration time for token
    * default: `3600s`. Must be parsable by [time.ParseDuration](https://pkg.go.dev/time#ParseDuration)

* `MOCK_OIDC_HOST`

    * default: `0.0.0.0`

* `MOCK_OIDC_PORT`

    * default: `3000`

* `MOCK_OIDC_PRODUCTION`

    * run in production mode or not
    * default: `false`

* `MOCK_OIDC_SESSION_COOKIE_NAME`

    * name for session cookie
    * default: `MOCK_OIDC_SESSION`

* `MOCK_OIDC_URI_BASE`

    * base url for application
    * default: `http://localhost:3000`

* `MOCK_OIDC_PUBLIC_KEY_PATH`

    * path to public key

* `MOCK_OIDC_PRIVATE_KEY_PATH`

    * path to private key

* `MOCK_OIDC_USERS_PATH`:

    * file containing json array of (allowed) user objects

* `MOCK_OIDC_CLIENTS_PATH`:

    * file containing json array of (allowed) client objects

You may also these in a `.env` file which makes
it easier to use during development.

## How to

### make public and private keys

In fact any tool that can make a public and a private SSL key set, will do.

For convenience we made the following script available, which requires openssl:

```
make keys
```

This stores the keys in `data/oidc.rsa.pub` and `data/oidc.rsa`

Set environment variables `MOCK_OIDC_PUBLIC_KEY_PATH` and `MOCK_OIDC_PRIVATE_KEY_PATH`

to the new public key and private key path respectively.


If you do not have `openssl` available, you MAY use the example

keys in `data/oidc.rsa.example` and `data/oidc.rsa.pub.example`

Command `make test_keys` copies these keys to `data/oidc.rsa.pub` and `data/oidc.rsa`,

if you prefer this.

### Add clients

Create a JSON file with the following structure:

```
[
    {"id": "my-client", "secret": "my-client-secret"}
]
```

File must contain an array of objects

Set environment variable `MOCK_OIDC_CLIENTS_PATH` to this path

### Add users

Create a JSON file with the following structure:

```
[
    {
        "id": "login-name",
        "claims": [
            {
              "name":  "name",
              "value": "my full name"
            },
            {
              "name":  "given_name",
              "value": "first-name"
            },
            {
              "name":  "family_name",
              "value": "family-name"
            },
            {
              "name":  "preferred_username",
              "value": "preferred-username"
            },
            {
              "name":  "email",
              "value": "joe@user.be"
            }
        ]
    }
]
```

File must contain an array of objects

Set environment variable `MOCK_OIDC_USERS_PATH` to this path

# Notes

* session cookie secrets are not configurable for the moment. These are reset on EVERY restart, thus expiring any cookies. The reason is that there is no backend store for the logins (aka tokens) for the moment, and session cookies would incorrectly assume a login token is still present in the backend after a restart.
