package protocol

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"

	"github.com/bolkedebruin/rdpgw/cmd/rdpgw/identity"
)

type fakeTransport struct {
	packets [][]byte
	next    int
	writes  [][]byte
}

func (f *fakeTransport) ReadPacket() (int, []byte, error) {
	if f.next >= len(f.packets) {
		return 0, nil, io.EOF
	}
	pkt := f.packets[f.next]
	f.next++
	return len(pkt), pkt, nil
}

func (f *fakeTransport) WritePacket(b []byte) (int, error) {
	f.writes = append(f.writes, append([]byte(nil), b...))
	return len(b), nil
}

func (f *fakeTransport) Close() error { return nil }

func channelCreatePacket(host string, port int) []byte {
	name := EncodeUTF16(host)
	var body []byte
	body = append(body, 0, 0) // resource size, alternative
	body = binary.LittleEndian.AppendUint16(body, uint16(port))
	body = binary.LittleEndian.AppendUint16(body, 0) // protocol
	body = binary.LittleEndian.AppendUint16(body, uint16(len(name)))
	body = append(body, name...)
	return createPacket(PKT_TYPE_CHANNEL_CREATE, body)
}

// TestCloseChannelKeepsTunnelOpen covers clients that close the channel while
// handling an RDP credential prompt and then open another channel on the same
// tunnel. The processor must not terminate the tunnel on the first close.
func TestCloseChannelKeepsTunnelOpen(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for i := 0; i < 2; i++ {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port

	client := &ClientConfig{}
	ft := &fakeTransport{packets: [][]byte{
		client.handshakeRequest(),
		createPacket(PKT_TYPE_TUNNEL_CREATE, make([]byte, 8)),
		createPacket(PKT_TYPE_TUNNEL_AUTH, []byte{0, 0}),
		channelCreatePacket("127.0.0.1", port),
		createPacket(PKT_TYPE_CLOSE_CHANNEL, nil),
		channelCreatePacket("127.0.0.1", port),
	}}

	channels := 0
	gw := &Gateway{CheckHost: func(context.Context, string) (bool, error) {
		channels++
		return true, nil
	}}
	tunnel := &Tunnel{
		User:         identity.NewUser(),
		transportIn:  ft,
		transportOut: ft,
	}
	_ = NewProcessor(gw, tunnel).Process(context.Background())

	if channels != 2 {
		t.Fatalf("channel creates = %d, want 2 (tunnel must survive the first close)", channels)
	}
}
