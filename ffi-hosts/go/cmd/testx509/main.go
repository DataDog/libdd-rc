package main

import (
	"fmt"
	"log"

	magictunnelv1 "github.com/DataDog/libdd-rc/ffi-hosts/go/rcproto/magic_tunnel"
	"github.com/DataDog/libdd-rc/ffi-hosts/go/rcx509"
)

func main() {
	if err := rcx509.SetLogHandler(func(level rcx509.LogLevel, target, message string) {
		log.Printf("[rust %s] %s: %s", level, target, message)
	}, rcx509.LogLevelDebug); err != nil {
		log.Fatal(err)
	}

	client, err := rcx509.NewClient("wss://config.datad0g.com/api/v2/ws")
	if err != nil {
		log.Fatal(err)
	}

	if err := client.RegisterHandler(magictunnelv1.Namespace_NAMESPACE_REMOTE_CONFIG, handleDebugService); err != nil {
		log.Fatal(err)
	}

	go client.Start()

	fmt.Println("Press Enter to exit...")
	fmt.Scanln()

	client.Close()
}
