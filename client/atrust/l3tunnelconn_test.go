package atrust

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"testing"
)

func TestReadDataRespPayloadAcceptsLengthPrefixedIPv4(t *testing.T) {
	packet := testIPv4Packet(20)
	frame := make([]byte, 2, 2+len(packet))
	binary.BigEndian.PutUint16(frame, uint16(len(packet)))
	frame = append(frame, packet...)

	payload, mode, err := readDataRespPayload(bufio.NewReader(bytes.NewReader(frame)))
	if err != nil {
		t.Fatalf("readDataRespPayload failed: %v", err)
	}
	if mode != "len" {
		t.Fatalf("mode = %q, want len", mode)
	}
	if !bytes.Equal(payload, packet) {
		t.Fatalf("payload = %x, want %x", payload, packet)
	}
}

func TestReadDataRespPayloadDoesNotMistakeTokenEnvelopeForLengthFrame(t *testing.T) {
	packet := testIPv4Packet(20)
	// tokenLen=0 and the first reserved byte=1 make the first two bytes look
	// like a one-byte raw frame to the old length-only discriminator.
	frame := []byte{0, 1, 0, 1, 0, byte(len(packet))}
	frame = append(frame, packet...)

	payload, mode, err := readDataRespPayload(bufio.NewReader(bytes.NewReader(frame)))
	if err != nil {
		t.Fatalf("readDataRespPayload failed: %v", err)
	}
	if mode != "token" {
		t.Fatalf("mode = %q, want token", mode)
	}
	packets, err := parseDataPayload(payload)
	if err != nil {
		t.Fatalf("parseDataPayload failed: %v", err)
	}
	if len(packets) != 1 || !bytes.Equal(packets[0], packet) {
		t.Fatalf("packets = %x, want one IPv4 packet %x", packets, packet)
	}
}

func testIPv4Packet(length int) []byte {
	packet := make([]byte, length)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(length))
	packet[8] = 64
	packet[9] = 6
	return packet
}
