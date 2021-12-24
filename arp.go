package main

import (
    "fmt"
    "net"

    "github.com/mdlayher/arp"
)

func main() {
    // Use ip addr on Ubuntu 20.04 to find the interface name of sender.
    ifi, err := net.InterfaceByName("enp3s0")
    if err != nil {
        fmt.Println(err)
        return
    }
	
    c, err := arp.Dial(ifi)
    if err != nil {
        fmt.Println(err)
        return
    }
    
    // the ip of device that we want to find.
    addr, err := c.Resolve(net.IPv4(192, 168, 0, 121))
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println(addr)
}
