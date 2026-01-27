package common

import (
	"errors"
	"net"

	"github.com/google/go-attestation/attest"
)

type SocketChannel struct {
	net.Conn
}

func (sc *SocketChannel) MeasurementLog() ([]byte, error) {
	return nil, errors.New("Not implemented")
}

func OpenTPMSocket(socketPath string) (attest.CommandChannelTPM20, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, err
	}
	return &SocketChannel{Conn: conn}, nil
}
