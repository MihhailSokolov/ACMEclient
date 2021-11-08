# ACME Client
This application implements ACME client with the addition of DNS and HTTP servers that are needed to facilitate local testing.
It contains the following components:
- ACME client: An ACME client which can interact with a standard-conforming ACME server.
- DNS server: A DNS server which resolves the DNS queries of the ACME server. It runs on UDP port 10053.
- Challenge HTTP server: An HTTP server to respond to http-01 queries of the ACME server. It runs on TCP port 5002.
- Certificate HTTPS server: An HTTPS server which uses a certificate obtained by the ACME client. It runs on TCP port 5001.
- Shutdown HTTP server: An HTTP server to receive a shutdown signal. It runs on TCP port 5003. 

The application also requires a running ACME server. [Pebble](https://github.com/letsencrypt/pebble) is recommended.

ACME client adheres to [RFC8555](https://tools.ietf.org/html/rfc8555) but does not implement the complete functionality, only main points.
The application is able to:
- use ACME to request and obtain certificates using the dns-01 and http-01 challenge (with fresh keys in every run),
- request and obtain certificates which contain aliases,
- request and obtain certificates with wildcard domain names, and
- revoke certificates after they have been issued by the ACME server.

## How to run
The application must be first compiled by running `./compile` and it is then run with `./run <...arguments...>`.

**Positional arguments:**
- `Challenge type`
  _(required, `{dns01 | http01}`)_ indicates which ACME challenge type the client performs. Valid options are `dns01` and `http01` for the `dns-01` and `http-01` challenges, respectively.

**Keyword arguments:**
- `--dir DIR_URL`
  _(required)_ `DIR_URL` is the directory URL of the ACME server that should be used.
- `--record IPv4_ADDRESS`
  _(required)_ `IPv4_ADDRESS` is the IPv4 address which must be returned by your DNS server for all A-record queries.
- `--domain DOMAIN`
  _(required, multiple)_ `DOMAIN` is the domain for which to request the certificate. If multiple `--domain` flags are present, a single certificate for multiple domains should be requested. Wildcard domains have no special flag and are simply denoted by, e.g., `*.example.net`.
- `--revoke`
  _(optional)_ If present, the application immediately revokes the certificate after obtaining it. In both cases, the application starts its HTTPS server and set it up to use the newly obtained certificate.

**Example:**
Consider the following invocation of `run`:
```
run dns01 --dir https://example.com/dir --record 1.2.3.4 --domain netsec.ethz.ch --domain syssec.ethz.ch
```
When invoked like this, the application obtains a single certificate valid for both `netsec.ethz.ch` and `syssec.ethz.ch`. It uses the ACME server at the URL `https://example.com/dir` and perform the `dns-01` challenge. The DNS server of the application responds with `1.2.3.4` to all requests for `A` records. Once the certificate has been obtained, the application starts its certificate HTTPS server and installs the obtained certificate in this server.