package main

import (
    "fmt"
    "net"

    "github.com/mdlayher/arp"
)

/*
Index is 1, HardwareAddr is 00:00:00:00:00:00
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
*/
func main() {
    // Use ip addr on Ubuntu 20.04 to find the interface of sender.
    ifi := &net.Interface{
        Index: 2,
        HardwareAddr: net.HardwareAddr{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff},
	}

    c, err := arp.Dial(ifi)
    if err != nil {
        fmt.Println(err)
        return
    }
    
    // the ip of device that we want to find.
    addr, err := c.Resolve(net.IPv4(192, 168, 0, 121).To4())
    if err != nil {
        fmt.Println(err)
        return
    }

    fmt.Println(addr)
}
