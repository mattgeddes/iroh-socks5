# iroh-socks5

## Overview

This is an Iroh Protocol implementation for being able to tunnel SOCKS5 proxy sessions over Iroh. It comes with an example binary to show a simple use case. It consists of an Iroh client that implements a SOCKS5 proxy server. SOCKS5 requests received by this server, are sent via the Iroh Protocol client to the Iroh Protocol server, which then enacts the SOCKS5 request.

There is some overlap between this use case and that of VPNs. This is not strictly a VPN, however. Just an application proxy over Iroh.

I've used LLMs to assist with some of the development -- especially the boring-ass SOCKS5 protocol implementation. All bugs are mine.

## Practical Example

### Start Server

On one machine, start the example Iroh server:

```sh
cargo run --example iroh-socks5 -- server
```

Make a note of the Endpoint ID.

### Start Client

On a second machine, start the example Iroh client (which is the SOCKS proxy server), including the server Endpoint ID from above:

```sh
cargo run --example iroh-socks5 -- client --remote <server-endpoint-id>
```

### Using the proxy

A simple baseline web request _without_ using the iroh-socks5 proxy:

```sh
curl ipinfo.io
```

A request through our Iroh SOCKS5 proxy:

```sh
curl --socks5 localhost:3128 ipinfo.io
```

## Custom relay

The example code binary allows the user to specify their own relay, rather than using the n0 test relays. Just pass `--relay <url>` on the command line.

## Keys

Both sides persist their identity in a key file (generated on first run):
`iroh-socks5-server.key` and `iroh-socks5-client.key` by default. Use the
`key` subcommand to inspect a key file's endpoint id.

## Access Control

The server example allows some basic access control by providing a whitelist of allows client public keys. It defaults to being open. See the `--allow` and `--allow-file` options for details.

## DNS

The server side also includes a feature-gated DNS resolver. This allows DNS requests to be intercepted and made against a DNS-over-HTTPS service, bypassing the server host's DNS stack and upstream. See the `--dns` option for details.

## License

Copyright 2026 Matthew Geddes

This project is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   https://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   https://opensource.org/licenses/MIT)

at your option. The same as the Iroh project.

