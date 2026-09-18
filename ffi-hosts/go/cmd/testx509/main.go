package main

import (
	"fmt"
	"log"
	"os"

	"github.com/DataDog/libdd-rc/ffi-hosts/go/rcx509"
)

// debugServicePingURI is the fully-qualified gRPC method name for the
// Remote Config team's example DebugService/Ping RPC.
const debugServicePingURI = "rc.x509.magic_tunnel.remote_config.v1.DebugService/Ping"

func main() {
	// Surface the client library's own tracing output on stderr, interleaved
	// with this example's own logging, for local debugging.
	if err := rcx509.EnableLogSink(os.Stderr); err != nil {
		log.Fatal(err)
	}

	client, err := rcx509.NewClient("wss://config.datad0g.com/api/v2/ws", "testx509-poc", "0.0.1")
	if err != nil {
		log.Fatal(err)
	}

	// Register a handler for the fully-qualified DebugService/Ping URI:
	if err := client.RegisterHandler(debugServicePingURI, handlePing); err != nil {
		log.Fatal(err)
	}

	// Register handlers for the fully-qualified RemoteQueriesControlService
	// URIs. One explicit controller instance backs all four methods: it is
	// the process's single owner of the admitted-run state.
	remoteQueries := newRemoteQueriesController()
	for uri, handler := range map[string]func(uint64, []byte) ([]byte, error){
		remoteQueriesResolveTargetURI: remoteQueries.handleResolveTarget,
		remoteQueriesStartRunURI:      remoteQueries.handleStartRun,
		remoteQueriesGetRunStatusURI:  remoteQueries.handleGetRunStatus,
		remoteQueriesCancelRunURI:     remoteQueries.handleCancelRun,
	} {
		if err := client.RegisterHandler(uri, handler); err != nil {
			log.Fatal(err)
		}
	}
	log.Print("registered the Remote Queries control-plane reference state machine: it simulates the control lifecycle only, executes no SQL, performs no upload, and loses all admitted-run state when the process restarts")

	go client.Start()

	fmt.Println("Press Enter to exit...")
	fmt.Scanln()

	client.Close()
}
