package main

import (
	"fmt"
	"net/http"
	"os"
	"strings"
)

func main() {
	if len(os.Args) == 2 {
		fmt.Println("UNSUPPORTED")
		os.Exit(0)
	} else if len(os.Args) != 3 {
		fmt.Println("usage: %s <host> <port>", os.Args[0])
		os.Exit(1)
	}

	url := "https://" + os.Args[1] + ":" + os.Args[2]

	// Perform a HTTP(s) Request
	_, err := http.Get(url)
	if err != nil {
		sslError := strings.Contains(err.Error(), "certificate") || strings.Contains(err.Error(), "handshake") ||
			strings.Contains(err.Error(), "verification error") || strings.Contains(err.Error(), "unexpected ServerKeyExchange")
		if sslError {
			fmt.Println("REJECT")
			os.Exit(0)
		}
		fmt.Println(err)
		os.Exit(1)
	}
	fmt.Println("ACCEPT")
	os.Exit(0)
}
