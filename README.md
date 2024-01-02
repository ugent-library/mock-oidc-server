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

* `MOCK_OIDC_PUBLIC_KEY`

    * public key

* `MOCK_OIDC_PUBLIC_KEY_PATH`

    * path to public key. Ignored when `MOCK_OIDC_PUBLIC_KEY` is given.
    * default: `.data/oidc.rsa.pub`

* `MOCK_OIDC_PRIVATE_KEY`

    * private key

* `MOCK_OIDC_PRIVATE_KEY_PATH`

    * path to private key. Ignored when `MOCK_OIDC_PRIVATE_KEY` is given.
    * default: `.data/oidc.rsa`

* `MOCK_OIDC_USERS`:

    * inline json array of (allowed) user objects.

* `MOCK_OIDC_USERS_PATH`:

    * file containing json array of (allowed) user objects. Ignored when `MOCK_OIDC_USERS` is given

* `MOCK_OIDC_CLIENTS`:

    * inline json array of (allowed) clients

* `MOCK_OIDC_CLIENTS_PATH`:

    * file containing json array of (allowed) client objects. Ignored when `MOCK_OIDC_CLIENTS` is given

You may also these in a `.env` file which makes
it easier to use during development.

## How to

### make public and private keys

In fact any tool that can make a public and a private SSL key set, will do.

For convenience we made the following script available, which requires openssl:

```
make keys
```

This store the keys in `.data/oidc.rsa.pub` and `.data/oidc.rsa`

Copy and paste their contents in environment variables `MOCK_OIDC_PUBLIC_KEY` and `MOCK_OIDC_PRIVATE_KEY`

if you prefer

### Add clients

Add a JSON object to the json array inside `MOCK_OIDC_CLIENTS`, with the following structure:

```
{"id": "my-client", "secret": "my-client-secret"}
```

### Add users

Add a JSON object to the json array inside `MOCK_OIDC_USERS`, with the following structure:

```
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
```

# Notes

* session cookie secrets are not configurable for the moment. These are reset on EVERY restart, thus expiring any cookies. The reason is that there is no backend store for the logins (aka tokens) for the moment, and session cookies would incorrectly assume a login token is still present in the backend after a restart.