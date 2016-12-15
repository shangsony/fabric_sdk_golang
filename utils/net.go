package utils

import (
	"net"
)

type Clienter struct {
	client  net.Conn
	isAlive bool
}

func (c *Clienter) Connect(proxy_server string) bool {
	if c.isAlive {
		return true
	} else {
		var err error
		c.client, err = net.Dial("tcp", proxy_server)
		if err != nil {
			return false
		}
		defer c.client.Close()
		c.isAlive = true
	}
	return c.isAlive
}
