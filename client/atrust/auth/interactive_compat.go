package auth

import (
	"encoding/json"
	"fmt"
	"strings"
)

// These parsing helpers remain solely for the Cedar InteractiveFlow
// compatibility surface. The upstream auth-handler path uses typed responses.
func parseTokenInput(input string) (string, int) {
	input = strings.TrimSpace(input)
	if strings.HasPrefix(input, "$") {
		return strings.TrimSpace(strings.TrimPrefix(input, "$")), 1
	}
	return input, 0
}

type graphCheckCodePoint struct {
	X int `json:"x"`
	Y int `json:"y"`
}

func canonicalizeGraphCheckCode(raw string, imgData []byte) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", fmt.Errorf("empty graph check code")
	}

	if payload, ok := parseGraphCheckCodeObject(trimmed); ok {
		if payload.Width <= 0 || payload.Height <= 0 {
			width, height, err := decodeImageSize(imgData)
			if err != nil {
				return "", fmt.Errorf("graph check code width/height missing and image size unavailable: %w", err)
			}
			payload.Width = width
			payload.Height = height
		}
		return marshalGraphCheckCode(payload)
	}

	if payload, ok := parseGraphCheckCodePointObjectArray(trimmed); ok {
		width, height, err := decodeImageSize(imgData)
		if err != nil {
			return "", fmt.Errorf("failed to decode captcha image size: %w", err)
		}
		payload.Width = width
		payload.Height = height
		return marshalGraphCheckCode(payload)
	}

	if payload, ok := parseGraphCheckCodeTupleArray(trimmed); ok {
		width, height, err := decodeImageSize(imgData)
		if err != nil {
			return "", fmt.Errorf("failed to decode captcha image size: %w", err)
		}
		payload.Width = width
		payload.Height = height
		return marshalGraphCheckCode(payload)
	}

	return "", fmt.Errorf("unsupported graph check code format")
}

func parseGraphCheckCodeObject(raw string) (graphCheckCodePayload, bool) {
	var payload graphCheckCodePayload
	if err := json.Unmarshal([]byte(raw), &payload); err != nil || !isValidCoordinates(payload.Coordinates) {
		return graphCheckCodePayload{}, false
	}
	return payload, true
}

func parseGraphCheckCodePointObjectArray(raw string) (graphCheckCodePayload, bool) {
	var points []graphCheckCodePoint
	if err := json.Unmarshal([]byte(raw), &points); err != nil || len(points) == 0 {
		return graphCheckCodePayload{}, false
	}
	coordinates := make([][]int, 0, len(points))
	for _, point := range points {
		coordinates = append(coordinates, []int{point.X, point.Y})
	}
	return graphCheckCodePayload{Coordinates: coordinates}, isValidCoordinates(coordinates)
}

func parseGraphCheckCodeTupleArray(raw string) (graphCheckCodePayload, bool) {
	var coordinates [][]int
	if err := json.Unmarshal([]byte(raw), &coordinates); err != nil || !isValidCoordinates(coordinates) {
		return graphCheckCodePayload{}, false
	}
	return graphCheckCodePayload{Coordinates: coordinates}, true
}
