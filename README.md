# libdd-rc

Open source client library for Datadog's [Remote Configuration].

This repo contains the following public libraries:

* [`rc-x509-client`]: core RC client with reusable public API.
* [`rc-x509-ffi`]: thin FFI wrapper over `rc-x509-client`.
* [`rc-x509-proto`]: protocol message definitions (inc. Magic Tunnel services).
* [`rcx509`]: a reference Go client built on-top of `rc-x509-ffi`.


[Remote Configuration]: https://docs.datadoghq.com/remote_configuration/
[`rc-x509-client`]: https://crates.io/crates/rc-x509-client
[`rc-x509-proto`]: https://crates.io/crates/rc-x509-proto
[`rc-x509-ffi`]: https://crates.io/crates/rc-x509-ffi
[`rcx509`]: ffi-hosts/go/rcx509

## Architecture

The client is designed to be embedded in applications that want to leverage
Datadog's Remote Configuration, where it handles all protocol, security, and
state management. 

The host application is responsible for initialising a `Ctx` handle, and driving
I/O to the Datadog datacenter using native I/O primitives:

```text
               ┌───────────── Host Runtime ────────────┐
               │               (Go, etc)               │
               │   ┌──────────┐         ┌──────────┐   │
               │   │  Native  │         │ Message  │   │
               │   │   I/O    │         │ Handlers │   │
               │   └──┬───▲───┘         └──────▲───┘   │
               └──────┼───┼────────────────────┼───────┘
                      │   │                    │        
               ┌──────────┼── rc-x509-ffi ─────┼───────┐
               │      │                                │
               │          │       Ctx          │       │
               │      │     (client handle)            │
               │          │                    │       │
               └──────┼────────────────────────────────┘
                      │   │                    │        
               ┌──────▼───┴─ rc-x509-client────┴───────┐
               │                                       │
               │              Event Loop               │
               │          & Protocol Handler           │
               │                                       │
               └───────────────────────────────────────┘
```

The client library invokes a callback to deliver pre-verified payloads to the
host application. Our reference `rcx509` Go client wraps the FFI interface to
provide an easy-to-use Go API which handles I/O and message routing.

Host applications wrote in Rust can bypass the FFI layer entirely, and benefit
from a no-`unsafe` binding to the client library itself.

## FFI API

The C-compatible FFI surface exposed to host applications:

```c
rc_init(..) → *mut Ctx            // create new client
rc_free(ctx)                      // stop client & release all resources

rc_conn_new(ctx) → *mut Conn      // create new client connection state
rc_conn_connected(conn, ..)       // mark connection as established
rc_conn_disconnected(conn)        // mark connection as disconnected
rc_conn_free(conn)                // release resources held by connection

rc_conn_send_callback(conn, cb)   // register callback used by client
rc_conn_recv(conn, data, len)     // passes data received for the connection
```

See the [FFI README](lib/rc-x509-ffi/README.md) for more details.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for commit signing requirements and
dependency workflow.
