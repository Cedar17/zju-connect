package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"image"
	"image/color"
	"image/png"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

func TestNewSessionRejectsUntrustedCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()

	session := NewSession(strings.TrimPrefix(server.URL, "https://"))
	if _, err := session.client.Get(server.URL); err == nil {
		t.Fatal("request to an untrusted TLS server succeeded")
	}
}

func TestInteractiveFlowPasswordCompletesWithoutLeakingResult(t *testing.T) {
	server := newInteractiveTestServer(t, interactiveScenario{})
	defer server.Close()

	flow := newTrustedFlow(t, server)
	prompt, err := flow.Begin()
	if err != nil || prompt.State != string(interactiveAwaitingMethod) || len(prompt.AuthMethods) != 1 {
		t.Fatalf("Begin() = %#v, %v", prompt, err)
	}
	if _, err := flow.SelectMethod("auth/psw", "Radius"); err != nil {
		t.Fatalf("SelectMethod: %v", err)
	}
	prompt, err = flow.SubmitCredentials("student", "password")
	if err != nil || prompt.State != string(interactiveAuthenticated) {
		t.Fatalf("SubmitCredentials() = %#v, %v", prompt, err)
	}
	if strings.Contains(fmt.Sprintf("%+v", prompt), "password") || strings.Contains(fmt.Sprintf("%+v", prompt), "session-cookie") {
		t.Fatalf("prompt leaked sensitive data: %#v", prompt)
	}
	result, ok := flow.Result()
	if !ok || result.Username != "student" || result.SID != "session-cookie" || len(result.ResourceData) == 0 {
		t.Fatalf("Result() = %#v, %v", result, ok)
	}
	flow.Cancel()
	if _, ok := flow.Result(); ok {
		t.Fatal("Cancel retained the authentication result")
	}
}

func TestInteractiveFlowPasswordCaptchaAndSecondarySMS(t *testing.T) {
	server := newInteractiveTestServer(t, interactiveScenario{captcha: true, secondarySMS: true})
	defer server.Close()

	flow := newTrustedFlow(t, server)
	if _, err := flow.Begin(); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := flow.SelectMethod("auth/psw", "Radius"); err != nil {
		t.Fatalf("SelectMethod: %v", err)
	}
	prompt, err := flow.SubmitCredentials("student", "password")
	if err != nil || prompt.State != string(interactiveAwaitingCaptcha) || prompt.CaptchaWidth != 2 || prompt.CaptchaHeight != 2 {
		t.Fatalf("captcha prompt = %#v, %v", prompt, err)
	}
	imageData, err := flow.PendingCaptchaImage()
	if err != nil || len(imageData) == 0 {
		t.Fatalf("PendingCaptchaImage = %d bytes, %v", len(imageData), err)
	}
	prompt, err = flow.SubmitCaptcha(`{"coordinates":[[1,1]],"width":2,"height":2}`)
	if err != nil || prompt.State != string(interactiveAwaitingSMS) {
		t.Fatalf("SubmitCaptcha = %#v, %v", prompt, err)
	}
	prompt, err = flow.SubmitSMSCode("123456")
	if err != nil || prompt.State != string(interactiveAuthenticated) {
		t.Fatalf("SubmitSMSCode = %#v, %v", prompt, err)
	}
}

func TestInteractiveFlowRejectsOutOfOrderInput(t *testing.T) {
	server := newInteractiveTestServer(t, interactiveScenario{})
	defer server.Close()
	flow := newTrustedFlow(t, server)
	if _, err := flow.SubmitSMSCode("123456"); err == nil {
		t.Fatal("out-of-order SMS input succeeded")
	}
	flow.Cancel()
	flow.Cancel()
	if _, err := flow.PendingCaptchaImage(); err == nil {
		t.Fatal("cancelled flow exposed a captcha image")
	}
}

type interactiveScenario struct {
	captcha      bool
	secondarySMS bool
}

func newTrustedFlow(t *testing.T, server *httptest.Server) *InteractiveFlow {
	t.Helper()
	flow, err := NewInteractiveFlow(strings.TrimPrefix(server.URL, "https://"))
	if err != nil {
		t.Fatalf("NewInteractiveFlow: %v", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	transport := flow.session.client.Transport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	return flow
}

func newInteractiveTestServer(t *testing.T, scenario interactiveScenario) *httptest.Server {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	publicKey := strings.ToUpper(privateKey.N.Text(16))
	imageData := captchaImage(t)
	var mu sync.Mutex
	passwordAttempts := 0

	return httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writeJSON := func(value any) {
			writer.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(writer).Encode(value); err != nil {
				t.Errorf("Encode: %v", err)
			}
		}
		switch request.URL.Path {
		case "/passport/v1/public/authConfig":
			writeJSON(map[string]any{"data": map[string]any{
				"isLogin":        0,
				"csrfToken":      "csrf",
				"pubKey":         publicKey,
				"pubKeyExp":      "65537",
				"antiReplayRand": "anti-replay",
				"authServerInfoList": []map[string]string{{
					"authType": "auth/psw", "loginDomain": "Radius", "authName": "Account",
				}},
			}})
		case "/passport/v1/auth/psw":
			mu.Lock()
			passwordAttempts++
			attempt := passwordAttempts
			mu.Unlock()
			if scenario.captcha && attempt == 1 {
				writeJSON(map[string]any{"code": 0, "message": "", "data": map[string]any{"graphCheckCodeEnable": 1}})
				return
			}
			if scenario.captcha {
				var payload map[string]any
				if err := json.NewDecoder(request.Body).Decode(&payload); err != nil || payload["graphCheckCode"] == nil {
					t.Errorf("captcha password payload = %#v, %v", payload, err)
				}
			}
			http.SetCookie(writer, &http.Cookie{Name: "sid", Value: "session-cookie", Path: "/"})
			writeJSON(map[string]any{"code": 0, "message": "", "data": map[string]any{"ticket": "ticket", "graphCheckCodeEnable": 0}})
		case "/passport/v1/public/checkCode":
			writer.Header().Set("Content-Type", "image/png")
			_, _ = writer.Write(imageData)
		case "/controller/v1/public/reportEnv":
			writeJSON(map[string]any{"code": 0})
		case "/passport/v1/auth/authCheck":
			data := map[string]any{}
			if scenario.secondarySMS {
				data["nextService"] = "auth/sms"
			}
			writeJSON(map[string]any{"code": 0, "data": data})
		case "/passport/v1/public/phoneNumber":
			writeJSON(map[string]any{"code": 0, "data": map[string]any{"phoneNumber": "138****0000"}})
		case "/passport/v1/auth/sms":
			if request.URL.Query().Get("action") == "sendsms" {
				writeJSON(map[string]any{"code": 0, "message": "sent", "data": map[string]any{"tips": "sent"}})
				return
			}
			writeJSON(map[string]any{"code": 0, "data": map[string]any{}})
		case "/passport/v1/user/onlineInfo":
			writeJSON(map[string]any{"code": 0, "data": map[string]any{"username": "student"}})
		case "/controller/v1/user/clientResource":
			writeJSON(map[string]any{"resource": "available"})
		default:
			t.Errorf("unexpected request: %s %s", request.Method, request.URL)
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
}

func captchaImage(t *testing.T) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, 2, 2))
	img.Set(0, 0, color.White)
	var encoded strings.Builder
	if err := png.Encode(&encoded, img); err != nil {
		t.Fatalf("Encode captcha: %v", err)
	}
	return []byte(encoded.String())
}

func TestRandomDeviceIDIsHex(t *testing.T) {
	deviceID, err := randomDeviceID()
	if err != nil || len(deviceID) != 32 {
		t.Fatalf("randomDeviceID = %q, %v", deviceID, err)
	}
	if _, err := hex.DecodeString(deviceID); err != nil {
		t.Fatalf("device ID is not hex: %v", err)
	}
}
