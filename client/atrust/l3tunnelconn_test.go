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

	payload, mode, err := readDataRespPayload(bufio.NewReader(bytes.NewReader(frame)), "")
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

func TestReadDataRespPayloadAcceptsLengthPrefixedIPv4Batch(t *testing.T) {
	first := testIPv4Packet(1400)
	second := testIPv4Packet(1400)
	payload := append(append([]byte{}, first...), second...)
	frame := make([]byte, 2, 2+len(payload))
	binary.BigEndian.PutUint16(frame, uint16(len(payload)))
	frame = append(frame, payload...)

	got, mode, err := readDataRespPayload(bufio.NewReader(bytes.NewReader(frame)), "")
	if err != nil {
		t.Fatalf("readDataRespPayload failed: %v", err)
	}
	if mode != "len" {
		t.Fatalf("mode = %q, want len", mode)
	}
	packets, remainder, err := parseLengthDataStream(got)
	if err != nil {
		t.Fatalf("parseLengthDataStream failed: %v", err)
	}
	if len(remainder) != 0 {
		t.Fatalf("remainder = %d bytes, want none", len(remainder))
	}
	if len(packets) != 2 || !bytes.Equal(packets[0], first) || !bytes.Equal(packets[1], second) {
		t.Fatalf("packets = %d, want two IPv4 packets", len(packets))
	}
}

func TestReadDataRespPayloadDoesNotMistakeTokenEnvelopeForLengthFrame(t *testing.T) {
	packet := testIPv4Packet(20)
	// tokenLen=0 and the first reserved byte=1 make the first two bytes look
	// like a one-byte raw frame to the old length-only discriminator.
	frame := []byte{0, 1, 0, 1, 0, byte(len(packet))}
	frame = append(frame, packet...)

	payload, mode, err := readDataRespPayload(bufio.NewReader(bytes.NewReader(frame)), "")
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

func TestLengthDataStreamReassemblesPacketAcrossFrames(t *testing.T) {
	first := testIPv4Packet(1400)
	second := testIPv4Packet(1400)
	third := testIPv4Packet(1400)
	fourth := testIPv4Packet(1400)
	stream := append(append(append(append([]byte{}, first...), second...), third...), fourth...)

	firstChunk := stream[:4096]
	secondChunk := stream[4096:]
	firstFrame := make([]byte, 2, 2+len(firstChunk))
	binary.BigEndian.PutUint16(firstFrame, uint16(len(firstChunk)))
	firstFrame = append(firstFrame, firstChunk...)
	secondFrame := make([]byte, 2, 2+len(secondChunk))
	binary.BigEndian.PutUint16(secondFrame, uint16(len(secondChunk)))
	secondFrame = append(secondFrame, secondChunk...)

	payload, mode, err := readDataRespPayload(bufio.NewReader(bytes.NewReader(firstFrame)), "")
	if err != nil {
		t.Fatalf("read first payload failed: %v", err)
	}
	if mode != "len" {
		t.Fatalf("first mode = %q, want len", mode)
	}
	packets, remainder, err := parseLengthDataStream(payload)
	if err != nil {
		t.Fatalf("parse first payload failed: %v", err)
	}
	if len(packets) != 2 || len(remainder) != 1296 {
		t.Fatalf("first packets/remainder = %d/%d, want 2/1296", len(packets), len(remainder))
	}

	payload, mode, err = readDataRespPayload(bufio.NewReader(bytes.NewReader(secondFrame)), mode)
	if err != nil {
		t.Fatalf("read continuation payload failed: %v", err)
	}
	if mode != "len" {
		t.Fatalf("continuation mode = %q, want len", mode)
	}
	packets, remainder, err = parseLengthDataStream(append(remainder, payload...))
	if err != nil {
		t.Fatalf("parse continuation payload failed: %v", err)
	}
	if len(packets) != 2 || len(remainder) != 0 {
		t.Fatalf("continuation packets/remainder = %d/%d, want 2/0", len(packets), len(remainder))
	}
	if !bytes.Equal(packets[0], third) || !bytes.Equal(packets[1], fourth) {
		t.Fatal("reassembled packets differ from input")
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
