package main

import (
	"fmt"
	"log"

	"github.com/DataDog/libdd-rc/ffi-hosts/go/rcx509"
)

// debugServicePingURI is the fully-qualified gRPC method name for the
// Remote Config team's example DebugService/Ping RPC.
const debugServicePingURI = "rc.x509.magic_tunnel.remote_config.v1.DebugService/Ping"

// remoteQueryServicePingURI is the fully-qualified gRPC method name for the
// Remote Queries team's smoke RemoteQueryService/Ping RPC.
const remoteQueryServicePingURI = "rc.x509.magic_tunnel.remote_queries.v1.RemoteQueryService/Ping"

func main() {
	client, err := rcx509.NewClient("wss://config.datad0g.com/api/v2/ws", "testx509-poc", "0.0.1")
	if err != nil {
		log.Fatal(err)
	}

	// Register a handler for the fully-qualified DebugService/Ping URI:
	if err := client.RegisterHandler(debugServicePingURI, handlePing); err != nil {
		log.Fatal(err)
	}

	// Register a handler for the fully-qualified RemoteQueryService/Ping URI:
	if err := client.RegisterHandler(remoteQueryServicePingURI, handleRemoteQueryPing); err != nil {
		log.Fatal(err)
	}

	go client.Start()

	fmt.Println("Press Enter to exit...")
	fmt.Scanln()

	client.Close()
}
