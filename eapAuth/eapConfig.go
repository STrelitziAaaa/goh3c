package eapAuth

import "net"

type Config struct {
	device net.Interface
}

func (c Config) getDevice() net.Interface {
	return c.device
}

