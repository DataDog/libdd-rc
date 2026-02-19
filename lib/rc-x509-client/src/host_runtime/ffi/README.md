# FFI Interface

This module defines a C compatible API for use as an FFI interface to the X509
client library.

## Design

This library aims to encapsulate all the state, logic, communication protocol
and message encoding details necessary to communicate with the RC delivery
backend.

All I/O is delegated to the host runtime which is responsible for creating a
connection to the RC backend, informing the client library of connection
lifecycle events (e.g. disconnects) while brokering data received from and sent
to the RC backend.

## Example Usage

```c
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Assuming the header provided is named "rc_client.h"
#include "rc_client.h"

// Define a callback function for handling outgoing network data (from the RC
// client lib -> RC backend).
SendRet socket_send_cb(const uint8_t* data, int32_t length) {
    printf("Sending %d bytes of data...\n", length);
    // TODO: host sends data over connection to RC backend asynchronously.
    return Success;
}

int main() {
    // Initialize the RC library.
    struct Ctx *ctx = rc_init();
    if (!ctx) {
        fprintf(stderr, "Failed to initialize context\n");
        return 1;
	}

    // Create a new connection handle.
    struct Conn *conn = rc_conn_new(ctx);
    if (!conn) {
        fprintf(stderr, "Failed to create connection\n");
        rc_free(ctx);
        return 1;
    }

	// TODO: host application dials a new connection here.

    // Setup the send callback and mark the connection as ready.
    rc_set_send_callback(conn, socket_send_cb);
    rc_conn_connected(conn);

    // EXAMPLE: simulate receiving data from the RC backend.
    const char *incoming_payload = "bananas!";
    int32_t payload_len = (int32_t)strlen(incoming_payload);

	// Pass the message bytes to the RC library.
    RecvRet result = rc_conn_recv(conn, (const uint8_t*)incoming_payload, payload_len);

    if (result == Success) {
        printf("Data processed successfully.\n");
    } else if (result == QueueFull) {
        printf("Warning: Receive queue is full.\n");
    }

    // Cleanup
	// TODO: host closes the network connection to the RC backend here.
    rc_conn_disconnected(conn);
    rc_conn_free(conn);
    rc_free(ctx);

    return 0;
}
```
