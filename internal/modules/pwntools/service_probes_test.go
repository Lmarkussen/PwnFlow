package pwntools

import (
	"bufio"
	"context"
	"encoding/binary"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// serveTCP answers one connection with handler and returns host and port.
func serveTCP(t *testing.T, handler func(net.Conn)) (string, int) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); handler(conn) }()
		}
	}()
	address := listener.Addr().(*net.TCPAddr)
	return "127.0.0.1", address.Port
}

func serveUDP(t *testing.T, handler func([]byte) []byte) (string, int) {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buffer := make([]byte, 2048)
		for {
			n, peer, err := conn.ReadFrom(buffer)
			if err != nil {
				return
			}
			if reply := handler(buffer[:n]); reply != nil {
				conn.WriteTo(reply, peer)
			}
		}
	}()
	return "127.0.0.1", conn.LocalAddr().(*net.UDPAddr).Port
}

func TestProbeRDP(t *testing.T) {
	reply := func(kind byte, value uint32) func(net.Conn) {
		return func(conn net.Conn) {
			request := make([]byte, 19)
			conn.Read(request)
			response := []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, kind, 0x00, 0x08, 0x00, 0, 0, 0, 0}
			binary.LittleEndian.PutUint32(response[15:], value)
			conn.Write(response)
		}
	}
	host, port := serveTCP(t, reply(0x02, 0))
	if result := probeService(context.Background(), "rdp", host, port); result.Outcome != "exposed" {
		t.Fatalf("standard RDP security accepted: %+v", result)
	}
	host, port = serveTCP(t, reply(0x03, 5))
	if result := probeService(context.Background(), "rdp", host, port); result.Outcome != "protected" || !strings.Contains(result.Detail, "Network Level Authentication required") {
		t.Fatalf("NLA required: %+v", result)
	}
	// TLS required for standard security, but TLS alone is accepted: no NLA.
	tlsOnly := func(conn net.Conn) {
		request := make([]byte, 19)
		conn.Read(request)
		kind, value := byte(0x03), uint32(1)
		if binary.LittleEndian.Uint32(request[15:]) == 1 {
			kind, value = 0x02, 1
		}
		response := []byte{0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, kind, 0x00, 0x08, 0x00, 0, 0, 0, 0}
		binary.LittleEndian.PutUint32(response[15:], value)
		conn.Write(response)
	}
	host, port = serveTCP(t, tlsOnly)
	if result := probeService(context.Background(), "rdp", host, port); result.Outcome != "exposed" || !strings.Contains(result.Detail, "TLS without CredSSP") {
		t.Fatalf("TLS without NLA: %+v", result)
	}
}

func TestProbeRedis(t *testing.T) {
	serve := func(reply string) func(net.Conn) {
		return func(conn net.Conn) {
			bufio.NewReader(conn).ReadString('\n')
			conn.Write([]byte(reply))
		}
	}
	host, port := serveTCP(t, serve("$40\r\n# Server\r\nredis_version:7.2.4\r\nos:Linux\r\n\r\n"))
	if result := probeService(context.Background(), "redis", host, port); result.Outcome != "exposed" || result.Evidence != "redis_version 7.2.4" {
		t.Fatalf("open redis: %+v", result)
	}
	host, port = serveTCP(t, serve("-NOAUTH Authentication required.\r\n"))
	if result := probeService(context.Background(), "redis", host, port); result.Outcome != "protected" {
		t.Fatalf("protected redis: %+v", result)
	}
}

func TestProbeElasticsearch(t *testing.T) {
	open := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"name":"node-1","cluster_name":"logs","version":{"number":"7.17.0"},"tagline":"You Know, for Search"}`))
	}))
	defer open.Close()
	host, portText, _ := net.SplitHostPort(strings.TrimPrefix(open.URL, "http://"))
	port, _ := strconv.Atoi(portText)
	if result := probeService(context.Background(), "elasticsearch", host, port); result.Outcome != "exposed" || result.Evidence != "logs 7.17.0" {
		t.Fatalf("open elasticsearch: %+v", result)
	}
	locked := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusUnauthorized) }))
	defer locked.Close()
	host, portText, _ = net.SplitHostPort(strings.TrimPrefix(locked.URL, "http://"))
	port, _ = strconv.Atoi(portText)
	if result := probeService(context.Background(), "elasticsearch", host, port); result.Outcome != "protected" {
		t.Fatalf("locked elasticsearch: %+v", result)
	}
}

func TestProbeMongoDB(t *testing.T) {
	serve := func(body string) func(net.Conn) {
		return func(conn net.Conn) {
			header := make([]byte, 4)
			conn.Read(header)
			length := binary.LittleEndian.Uint32(header)
			rest := make([]byte, length-4)
			conn.Read(rest)
			reply := make([]byte, 4, 64)
			reply = append(reply, make([]byte, 12)...)
			reply = append(reply, []byte(body)...)
			binary.LittleEndian.PutUint32(reply, uint32(len(reply)))
			conn.Write(reply)
		}
	}
	host, port := serveTCP(t, serve("databases\x00name\x00admin\x00name\x00crm\x00ok"))
	if result := probeService(context.Background(), "mongodb", host, port); result.Outcome != "exposed" || result.Evidence != "2 database name(s) returned" {
		t.Fatalf("open mongodb: %+v", result)
	}
	host, port = serveTCP(t, serve("command listDatabases requires authentication"))
	if result := probeService(context.Background(), "mongodb", host, port); result.Outcome != "protected" {
		t.Fatalf("protected mongodb: %+v", result)
	}
}

func TestProbeSNMPAndIPMI(t *testing.T) {
	host, port := serveUDP(t, func(request []byte) []byte {
		if !strings.Contains(string(request), "private") {
			return nil // public is refused silently, as agents do
		}
		oid := []byte{0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00}
		value := append([]byte{0x04, byte(len("Cisco IOS 15.2"))}, "Cisco IOS 15.2"...)
		return append(append([]byte{0x30, 0x00}, oid...), value...)
	})
	if result := probeService(context.Background(), "snmp", host, port); result.Outcome != "exposed" || !strings.Contains(result.Detail, `"private"`) || result.Evidence != "Cisco IOS 15.2" {
		t.Fatalf("snmp: %+v", result)
	}
	host, port = serveUDP(t, func([]byte) []byte {
		reply := make([]byte, 30)
		reply[20], reply[22], reply[23] = 0x00, 0x80, 0x04 // completion ok, IPMI 2.0, anonymous login
		return reply
	})
	if result := probeService(context.Background(), "ipmi", host, port); result.Outcome != "exposed" || !strings.Contains(result.Evidence, "anonymous login enabled") {
		t.Fatalf("ipmi: %+v", result)
	}
}

func TestSNMPGetRequestShape(t *testing.T) {
	packet := snmpGetRequest("public")
	if packet[0] != 0x30 || int(packet[1]) != len(packet)-2 || !strings.Contains(string(packet), "public") {
		t.Fatalf("% x", packet)
	}
}
