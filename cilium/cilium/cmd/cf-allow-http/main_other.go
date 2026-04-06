//go:build !linux

package main

import "fmt"

func main() {
	fmt.Println("cf-allow-http is Linux-only because it needs XDP/eBPF support.")
}
