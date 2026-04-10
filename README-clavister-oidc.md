# Clavister OneConnect OIDC Authentication

This fork adds support for Clavister NetWall firewalls that use OpenID Connect (OIDC) for OneConnect VPN authentication.

## Background

Clavister OneConnect uses the AnyConnect protocol but extends it with an OIDC authenticator. When a Clavister NetWall is configured with OIDC authentication (e.g., via Microsoft Entra ID), the server responds to the standard `config-auth` init request with:

```xml
<config-auth client="vpn" type="auth-request">
  <auth id="main" authenticator="oidc">
    <discovery-endpoint>https://login.microsoftonline.com/.../v2.0/.well-known/openid-configuration</discovery-endpoint>
    <client-id>your-client-id</client-id>
    <nonce>server-generated-nonce</nonce>
  </auth>
</config-auth>
```

The upstream openconnect client does not handle this response type. This fork implements the full OIDC flow.

## How it works

1. OpenConnect sends the standard AnyConnect auth init request
2. The server responds with OIDC parameters (discovery endpoint, client ID, nonce)
3. OpenConnect fetches the OIDC discovery document to find the authorization and token endpoints
4. A browser is opened to the OIDC authorization URL with a localhost callback
5. The user authenticates in the browser (e.g., Microsoft Entra ID login)
6. The browser redirects to `http://127.0.0.1:<port>/oneconnect/oauth/` with an authorization code
7. OpenConnect exchanges the code for an `id_token` at the token endpoint
8. The `id_token` is sent back to the server in an `<id-token>` element in the auth-reply
9. The server validates the token and establishes the VPN session

## Building

This is a standard autotools project. From a git checkout:

```bash
# Generate the configure script
./autogen.sh

# Configure the build
./configure

# Build
make
```

**Prerequisites** (package names for Arch/CachyOS):

```bash
sudo pacman -S autoconf automake libtool pkg-config gnutls libxml2 zlib
```

On Debian/Ubuntu:

```bash
sudo apt install autoconf automake libtool pkg-config libgnutls28-dev libxml2-dev zlib1g-dev
```

Run `./configure --help` to see available options (e.g., `--with-openssl` to use OpenSSL instead of GnuTLS).

## Usage

```bash
sudo openconnect vpn.example.com
```

No special flags are needed. OpenConnect automatically detects the OIDC auth-request and handles it. A browser window will open for authentication.

### Requirements

- `curl` must be available in PATH (used for OIDC discovery and token exchange)
- `xdg-open` or a configured `--external-browser` for opening the browser
- The browser is automatically launched as the original user when running under `sudo`

### Troubleshooting

**Browser fails to open**: If running via `sudo`, the browser is launched as the original user using `SUDO_USER`. If this fails, try setting display variables:

```bash
sudo DISPLAY=$DISPLAY XAUTHORITY=$XAUTHORITY openconnect vpn.example.com
```

**Authentication fails with 401**: Ensure the Clavister NetWall has OIDC properly configured with the correct redirect URI (`http://127.0.0.1/oneconnect/oauth/`). Microsoft Entra ID allows any port for localhost redirects.

## Clavister server configuration

On the Clavister NetWall side, OIDC authentication requires:

1. An OIDC provider object configured under Policies > User Authentication > User Directories > OIDC
2. The OIDC provider linked to the OneConnect interface
3. In the Entra ID (Azure AD) app registration:
   - Platform: Mobile and desktop applications
   - Redirect URI: `http://127.0.0.1/oneconnect/oauth/`
   - Public client flows enabled

Refer to the [Clavister Knowledge Base](https://kb.clavister.com/400556674/how-to---configure-oidc-with-entra-id-and-netwall) for detailed server-side setup instructions.

## Protocol details

The OIDC extension uses the following XML element in the auth-reply:

```xml
<config-auth client="vpn" type="auth-reply" aggregate-auth-version="2">
  <version who="vpn">v9.12</version>
  <device-id>linux-64</device-id>
  <auth id="main">
    <id-token>eyJ...</id-token>
  </auth>
</config-auth>
```

The server validates:
- Token signature (via the OIDC provider's JWKS)
- Token audience matches the configured client ID
- Token expiration
- Nonce matches the one sent in the auth-request

The completion response from Clavister differs slightly from Cisco:
- Uses `<title>` instead of `<message>` in the auth success element
- Does not include `server-cert-hash` in the config
