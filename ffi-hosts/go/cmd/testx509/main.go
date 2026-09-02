package main

import (
	"fmt"
	"log"

	"github.com/DataDog/libdd-rc/ffi-hosts/go/rcx509"
)

func main() {
	client, err := rcx509.NewClient("wss://config.datad0g.com/api/v2/ws")
	if err != nil {
		log.Fatal(err)
	}

	go client.Start()

	fmt.Println("Press Enter to exit...")
	fmt.Scanln()

	client.Close()
}
