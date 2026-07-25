package atrust

import (
	"crypto/tls"
	"testing"
)

func TestNodeTLSConfigDefaultsToSystemVerification(t *testing.T) {
	client := NewClient("user", "sid", "device", "")

	config := client.nodeTLSConfigForDial()
	if config.InsecureSkipVerify {
		t.Fatal("default node TLS config must use Go certificate verification")
	}
}

func TestNodeTLSConfigIsCloned(t *testing.T) {
	client := NewClient("user", "sid", "device", "")
	provided := &tls.Config{
		ServerName:         "node.example.test",
		InsecureSkipVerify: true, // #nosec G402 -- verifies the clone boundary, not a production policy.
	}

	client.SetNodeTLSConfig(provided)
	provided.ServerName = "mutated.example.test"

	first := client.nodeTLSConfigForDial()
	if first.ServerName != "node.example.test" {
		t.Fatalf("stored ServerName = %q, want node.example.test", first.ServerName)
	}
	first.ServerName = "caller-mutated.example.test"

	second := client.nodeTLSConfigForDial()
	if second.ServerName != "node.example.test" {
		t.Fatalf("returned config was not cloned; got %q", second.ServerName)
	}
}

func TestSetNilNodeTLSConfigRestoresSystemVerification(t *testing.T) {
	client := NewClient("user", "sid", "device", "")
	client.SetNodeTLSConfig(&tls.Config{InsecureSkipVerify: true}) // #nosec G402 -- exercised reset behavior.
	client.SetNodeTLSConfig(nil)

	if config := client.nodeTLSConfigForDial(); config.InsecureSkipVerify {
		t.Fatal("nil node TLS config must restore Go certificate verification")
	}
}
