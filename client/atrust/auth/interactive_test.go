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
	"time"
)

func TestNewSessionRejectsUntrustedCertificate(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()

	session := NewSession(strings.TrimPrefix(server.URL, "https://"))
	if _, err := session.client.Get(server.URL); err == nil {
		t.Fatal("request to an untrusted TLS server succeeded")
	}
}

func TestInteractiveFlowOptionsEnforceStrictTLS(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer server.Close()
	host := strings.TrimPrefix(server.URL, "https://")
	deviceID := strings.Repeat("a", 32)

	strict, err := NewInteractiveFlowWithOptions(host, InteractiveFlowOptions{
		DeviceID:  deviceID,
		StrictTLS: true,
	})
	if err != nil {
		t.Fatalf("NewInteractiveFlowWithOptions(strict): %v", err)
	}
	if _, err := strict.session.client.Get(server.URL); err == nil {
		t.Fatal("strict interactive flow accepted an untrusted certificate")
	}

	compatible, err := NewInteractiveFlowWithOptions(host, InteractiveFlowOptions{
		DeviceID: deviceID,
	})
	if err != nil {
		t.Fatalf("NewInteractiveFlowWithOptions(compatible): %v", err)
	}
	if _, err := compatible.session.client.Get(server.URL); err != nil {
		t.Fatalf("explicit non-strict compatibility flow rejected test certificate: %v", err)
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

func TestInteractiveFlowExpiredSessionReauthenticatesWithSecondarySMSOnly(t *testing.T) {
	server := newInteractiveTestServer(t, interactiveScenario{
		secondarySMS:        true,
		expectedPasswordSID: "expired-session-cookie",
	})
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "https://")
	const deviceID = "11111111111111111111111111111111"
	flow, err := NewInteractiveFlowWithDeviceID(host, deviceID)
	if err != nil {
		t.Fatalf("NewInteractiveFlowWithDeviceID: %v", err)
	}
	trustInteractiveFlow(t, flow, server)

	authData, err := json.Marshal(ClientAuthData{
		DeviceID: "22222222222222222222222222222222",
		Cookies:  []Cookie{{Host: host, Scheme: "https", Name: "sid", Value: "expired-session-cookie"}},
	})
	if err != nil {
		t.Fatalf("Marshal auth data: %v", err)
	}

	prompt, err := flow.Resume(authData)
	if err != nil || prompt.State != string(interactiveAwaitingMethod) || prompt.Code != "sessionExpired" {
		t.Fatalf("Resume() = %#v, %v", prompt, err)
	}
	if _, err := flow.SelectMethod("auth/psw", "Radius"); err != nil {
		t.Fatalf("SelectMethod: %v", err)
	}

	prompt, err = flow.SubmitCredentials("student", "saved-password")
	if err != nil || prompt.State != string(interactiveAwaitingSMS) {
		t.Fatalf("SubmitCredentials() = %#v, %v, want SMS without captcha", prompt, err)
	}
	if prompt.CaptchaWidth != 0 || prompt.CaptchaHeight != 0 {
		t.Fatalf("SMS-only prompt exposed captcha dimensions: %#v", prompt)
	}
	if _, err := flow.PendingCaptchaImage(); err == nil {
		t.Fatal("SMS-only reauthentication exposed a captcha image")
	}

	prompt, err = flow.SubmitSMSCode("123456")
	if err != nil || prompt.State != string(interactiveAuthenticated) {
		t.Fatalf("SubmitSMSCode() = %#v, %v", prompt, err)
	}
	result, ok := flow.Result()
	if !ok {
		t.Fatal("SMS-only reauthentication did not produce a result")
	}
	var refreshed ClientAuthData
	if err := json.Unmarshal(result.AuthData, &refreshed); err != nil {
		t.Fatalf("Unmarshal refreshed auth data: %v", err)
	}
	if refreshed.DeviceID != deviceID {
		t.Fatalf("device ID = %q, want stable caller identity %q", refreshed.DeviceID, deviceID)
	}
	if got := cookieValue(refreshed.Cookies, "sid"); got != "session-cookie" {
		t.Fatalf("refreshed sid = %q, want session-cookie", got)
	}
}

func TestSessionLoginReturnsCookiesFromRefreshedJar(t *testing.T) {
	server := newInteractiveTestServer(t, interactiveScenario{alreadyLoggedIn: true})
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "https://")
	result, err := newTLSTestSession(server).Login(nil, LoginOptions{
		DeviceID: "0123456789abcdef0123456789abcdef",
		Cookies:  []Cookie{{Host: host, Scheme: "https", Name: "sid", Value: "stored-session-cookie"}},
	})
	if err != nil {
		t.Fatalf("Login: %v", err)
	}
	if result.SID != "refreshed-session-cookie" {
		t.Fatalf("SID = %q, want refreshed-session-cookie", result.SID)
	}
	if got := cookieValue(result.Cookies, "sid"); got != "refreshed-session-cookie" {
		t.Fatalf("returned sid cookie = %q, want refreshed-session-cookie", got)
	}
}

func TestInteractiveFlowResumesAuthenticatedSessionAndRefreshesCookies(t *testing.T) {
	server := newInteractiveTestServer(t, interactiveScenario{alreadyLoggedIn: true})
	defer server.Close()

	flow := newTrustedFlow(t, server)
	host := strings.TrimPrefix(server.URL, "https://")
	authData, err := json.Marshal(ClientAuthData{
		DeviceID: "ABCDEF0123456789ABCDEF0123456789",
		Cookies: []Cookie{
			{Host: host, Scheme: "https", Name: "sid", Value: "stored-session-cookie"},
			{Host: host, Scheme: "https", Name: "sid.sig", Value: "stored-signature"},
		},
	})
	if err != nil {
		t.Fatalf("Marshal auth data: %v", err)
	}

	prompt, err := flow.Resume(authData)
	if err != nil || prompt.State != string(interactiveAuthenticated) {
		t.Fatalf("Resume() = %#v, %v", prompt, err)
	}
	result, ok := flow.Result()
	if !ok || result.Username != "student" || result.SID != "refreshed-session-cookie" || len(result.ResourceData) == 0 {
		t.Fatalf("Result() = %#v, %v", result, ok)
	}
	var refreshed ClientAuthData
	if err := json.Unmarshal(result.AuthData, &refreshed); err != nil {
		t.Fatalf("Unmarshal refreshed auth data: %v", err)
	}
	if refreshed.DeviceID != "ABCDEF0123456789ABCDEF0123456789" {
		t.Fatalf("device ID changed during resume: %q", refreshed.DeviceID)
	}
	if got := cookieValue(refreshed.Cookies, "sid"); got != "refreshed-session-cookie" {
		t.Fatalf("refreshed sid = %q", got)
	}
}

func TestInteractiveFlowContinuesRejectedSessionWithSameIdentity(t *testing.T) {
	server := newInteractiveTestServer(t, interactiveScenario{})
	defer server.Close()

	flow := newTrustedFlow(t, server)
	host := strings.TrimPrefix(server.URL, "https://")
	authData, err := json.Marshal(ClientAuthData{
		DeviceID: "0123456789abcdef0123456789abcdef",
		Cookies:  []Cookie{{Host: host, Scheme: "https", Name: "sid", Value: "expired-session-cookie"}},
	})
	if err != nil {
		t.Fatalf("Marshal auth data: %v", err)
	}

	prompt, err := flow.Resume(authData)
	if err != nil || prompt.State != string(interactiveAwaitingMethod) || prompt.Code != "sessionExpired" {
		t.Fatalf("Resume() = %#v, %v, want recoverable method prompt", prompt, err)
	}
	if _, ok := flow.Result(); ok {
		t.Fatal("rejected session produced an authentication result")
	}
}

func TestInteractiveFlowUsesCallerDeviceIDDuringResume(t *testing.T) {
	server := newInteractiveTestServer(t, interactiveScenario{alreadyLoggedIn: true})
	defer server.Close()

	host := strings.TrimPrefix(server.URL, "https://")
	const expectedDeviceID = "11111111111111111111111111111111"
	flow, err := NewInteractiveFlowWithDeviceID(host, expectedDeviceID)
	if err != nil {
		t.Fatalf("NewInteractiveFlowWithDeviceID: %v", err)
	}
	trustInteractiveFlow(t, flow, server)
	authData, err := json.Marshal(ClientAuthData{
		DeviceID: "22222222222222222222222222222222",
		Cookies:  []Cookie{{Host: host, Scheme: "https", Name: "sid", Value: "stored-session-cookie"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := flow.Resume(authData); err != nil {
		t.Fatalf("Resume: %v", err)
	}
	result, ok := flow.Result()
	if !ok {
		t.Fatal("Resume did not produce a result")
	}
	var refreshed ClientAuthData
	if err := json.Unmarshal(result.AuthData, &refreshed); err != nil {
		t.Fatal(err)
	}
	if refreshed.DeviceID != expectedDeviceID {
		t.Fatalf("device ID = %q, want caller identity", refreshed.DeviceID)
	}
}

func TestInteractiveFlowReturnsRecoverableCredentialRejection(t *testing.T) {
	server := newInteractiveTestServer(t, interactiveScenario{rejectPassword: true})
	defer server.Close()

	flow := newTrustedFlow(t, server)
	if _, err := flow.Begin(); err != nil {
		t.Fatal(err)
	}
	if _, err := flow.SelectMethod("auth/psw", "Radius"); err != nil {
		t.Fatal(err)
	}
	prompt, err := flow.SubmitCredentials("student", "wrong")
	if err != nil || prompt.State != string(interactiveAwaitingCredentials) || prompt.Code != "credentialsRejected" {
		t.Fatalf("SubmitCredentials() = %#v, %v", prompt, err)
	}
}

func TestInteractiveFlowExposesServerTokenChallenges(t *testing.T) {
	for _, service := range []string{"auth/totp", "auth/radius", "auth/challenge"} {
		t.Run(service, func(t *testing.T) {
			server := newInteractiveTestServer(t, interactiveScenario{secondaryService: service})
			defer server.Close()

			flow := newTrustedFlow(t, server)
			if _, err := flow.Begin(); err != nil {
				t.Fatal(err)
			}
			if _, err := flow.SelectMethod("auth/psw", "Radius"); err != nil {
				t.Fatal(err)
			}
			prompt, err := flow.SubmitCredentials("student", "correct")
			if err != nil || prompt.State != string(interactiveAwaitingToken) || prompt.ChallengeKind != service {
				t.Fatalf("SubmitCredentials() = %#v, %v", prompt, err)
			}
			prompt, err = flow.SubmitToken("123456")
			if err != nil || prompt.State != string(interactiveAuthenticated) {
				t.Fatalf("SubmitToken() = %#v, %v", prompt, err)
			}
		})
	}
}

func TestInteractiveFlowRejectsIncompleteSessionBeforeNetworking(t *testing.T) {
	server := newInteractiveTestServer(t, interactiveScenario{})
	defer server.Close()
	flow := newTrustedFlow(t, server)

	if _, err := flow.Resume([]byte(`{"cookies":[]}`)); err == nil {
		t.Fatal("incomplete authentication session was accepted")
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

func TestInteractiveFlowCancelInterruptsActiveRequestAndClearsState(t *testing.T) {
	requestStarted := make(chan struct{})
	requestRelease := make(chan struct{})
	server := newInteractiveTestServer(t, interactiveScenario{
		blockPassword:   true,
		passwordStarted: requestStarted,
		passwordRelease: requestRelease,
	})
	defer server.Close()
	defer close(requestRelease)

	flow := newTrustedFlow(t, server)
	if _, err := flow.Begin(); err != nil {
		t.Fatalf("Begin: %v", err)
	}
	if _, err := flow.SelectMethod("auth/psw", "Radius"); err != nil {
		t.Fatalf("SelectMethod: %v", err)
	}

	operationDone := make(chan error, 1)
	go func() {
		_, err := flow.SubmitCredentials("student", "password")
		operationDone <- err
	}()
	select {
	case <-requestStarted:
	case <-time.After(time.Second):
		t.Fatal("password request did not start")
	}

	startedAt := time.Now()
	flow.Cancel()
	if elapsed := time.Since(startedAt); elapsed > 250*time.Millisecond {
		t.Fatalf("Cancel blocked for %s", elapsed)
	}
	flow.session.connectionTracker.mu.Lock()
	connections := len(flow.session.connectionTracker.connections)
	flow.session.connectionTracker.mu.Unlock()
	if connections != 0 {
		t.Fatalf("Cancel left %d active authentication connections", connections)
	}
	select {
	case err := <-operationDone:
		if err == nil {
			t.Fatal("cancelled password request unexpectedly succeeded")
		}
	case <-time.After(time.Second):
		t.Fatal("authentication operation did not return after cancellation")
	}

	if _, ok := flow.Result(); ok {
		t.Fatal("cancelled request retained an authentication result")
	}
	waitForInteractiveCancellation(t, flow)
}

func waitForInteractiveCancellation(t *testing.T, flow *InteractiveFlow) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		flow.mu.Lock()
		cleared := flow.state == interactiveCancelled &&
			flow.username == "" &&
			flow.password == "" &&
			flow.phone == "" &&
			flow.smsCode == "" &&
			len(flow.captcha) == 0 &&
			flow.result == nil
		flow.mu.Unlock()
		if cleared {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("cancelled flow did not clear its sensitive state")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

type interactiveScenario struct {
	captcha             bool
	secondarySMS        bool
	secondaryService    string
	alreadyLoggedIn     bool
	blockPassword       bool
	rejectPassword      bool
	expectedPasswordSID string
	passwordStarted     chan struct{}
	passwordRelease     <-chan struct{}
}

func newTrustedFlow(t *testing.T, server *httptest.Server) *InteractiveFlow {
	t.Helper()
	host := strings.TrimPrefix(server.URL, "https://")
	flow, err := NewInteractiveFlow(host)
	if err != nil {
		t.Fatalf("NewInteractiveFlow: %v", err)
	}
	trustInteractiveFlow(t, flow, server)
	return flow
}

func trustInteractiveFlow(t *testing.T, flow *InteractiveFlow, server *httptest.Server) {
	t.Helper()
	host := strings.TrimPrefix(server.URL, "https://")
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	flow.session = newSession(host, &tls.Config{RootCAs: pool})
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
			if scenario.alreadyLoggedIn {
				if cookie, err := request.Cookie("sid"); err != nil || cookie.Value != "stored-session-cookie" {
					t.Errorf("resume authConfig sid cookie = %#v, %v", cookie, err)
				}
				http.SetCookie(writer, &http.Cookie{Name: "sid", Value: "refreshed-session-cookie", Path: "/"})
				writeJSON(map[string]any{"data": map[string]any{
					"isLogin":   1,
					"csrfToken": "csrf",
				}})
				return
			}
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
			if scenario.expectedPasswordSID != "" {
				cookie, err := request.Cookie("sid")
				if err != nil || cookie.Value != scenario.expectedPasswordSID {
					t.Errorf("password sid cookie = %#v, %v, want %q", cookie, err, scenario.expectedPasswordSID)
				}
			}
			if scenario.blockPassword {
				close(scenario.passwordStarted)
				<-scenario.passwordRelease
				return
			}
			if scenario.rejectPassword {
				writeJSON(map[string]any{"code": 1001, "message": "invalid credentials", "data": map[string]any{"graphCheckCodeEnable": 0}})
				return
			}
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
			} else if scenario.secondaryService != "" {
				data["nextService"] = scenario.secondaryService
			}
			writeJSON(map[string]any{"code": 0, "data": data})
		case "/passport/v1/auth/token", "/passport/v1/auth/challenge":
			writeJSON(map[string]any{"code": 0, "data": map[string]any{}})
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

func cookieValue(cookies []Cookie, name string) string {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie.Value
		}
	}
	return ""
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
