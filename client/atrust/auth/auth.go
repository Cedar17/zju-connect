package auth

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	mathrand "math/rand"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/mythologyli/zju-connect/log"
)

const (
	UserAgent    = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) aTrustTray/2.4.10.50 Chrome/83.0.4103.94 Electron/9.0.2 Safari/537.36 aTrustTray-Linux-Plat-Ubuntu-x64 SPCClientType"
	maxAttempts  = 5
	maxAuthSteps = 8
)

// ErrSessionInvalid means the server explicitly rejected a restored session.
// Callers may discard persisted authentication state only for this error; a
// transport or TLS failure does not prove that the session has expired.
var ErrSessionInvalid = errors.New("aTrust session is not authenticated")

// ErrCredentialsRejected identifies an explicit password rejection. It is
// recoverable inside an interactive flow and must not be used for transport,
// TLS, or server availability failures.
var ErrCredentialsRejected = errors.New("aTrust credentials rejected")

var sharedParams = url.Values{
	"clientType": {"SDPClient"},
	"platform":   {"Linux"},
	"lang":       {"en-US"},
}

func WithSharedParams(extra url.Values) url.Values {
	combined := make(url.Values, len(sharedParams)+len(extra))
	for k, v := range sharedParams {
		combined[k] = append([]string(nil), v...)
	}

	for k, v := range extra {
		for _, val := range v {
			// notice: not Add()
			combined.Set(k, val)
		}
	}

	return combined
}

type Cookie struct {
	Host   string `json:"host"`
	Scheme string `json:"scheme"`
	Name   string `json:"name"`
	Value  string `json:"value"`
}

type ClientAuthData struct {
	Cookies  []Cookie `json:"cookies"`
	DeviceID string   `json:"device_id"`
}

type Session struct {
	client            *http.Client
	requestContext    context.Context
	cancelRequests    context.CancelFunc
	connectionTracker *connectionTracker
	deviceID          string
	username          string
	totpSecret        string

	baseHost string
	baseURL  string

	rid            string
	env            string
	csrfToken      string
	pubKey         string
	pubKeyExp      string
	antiReplayRand string
	ticket         string

	response map[string]json.RawMessage
}

func NewSession(server string, dialContext ...func(context.Context, string, string) (net.Conn, error)) *Session {
	return newSession(server, nil, dialContext...)
}

func newSession(server string, tlsConfig *tls.Config, dialContext ...func(context.Context, string, string) (net.Conn, error)) *Session {
	// Leave TLS verification enabled. The Android client must reject an
	// untrusted certificate or a hostname mismatch before credentials are sent.
	baseDialContext := (&net.Dialer{}).DialContext
	if len(dialContext) > 0 && dialContext[0] != nil {
		baseDialContext = dialContext[0]
	}
	connectionTracker := newConnectionTracker(baseDialContext)
	tr := &http.Transport{DialContext: connectionTracker.dialContext}
	if tlsConfig != nil {
		tr.TLSClientConfig = tlsConfig.Clone()
	}
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Transport: tr, Jar: jar, Timeout: 20 * time.Second}
	requestContext, cancelRequests := context.WithCancel(context.Background())

	return &Session{
		client:            client,
		requestContext:    requestContext,
		cancelRequests:    cancelRequests,
		connectionTracker: connectionTracker,
		baseHost:          server,
		baseURL:           "https://" + server,
		rid:               base64.StdEncoding.EncodeToString([]byte(server)),
		response:          make(map[string]json.RawMessage),
	}
}

// do binds every authentication request to the session lifetime. Cancelling
// the session interrupts active dials, TLS handshakes, and response reads.
func (s *Session) do(request *http.Request) (*http.Response, error) {
	return s.client.Do(request.WithContext(s.requestContext))
}

func (s *Session) cancel() {
	s.cancelRequests()
	s.connectionTracker.closeAll()
	s.client.CloseIdleConnections()
}

type connectionTracker struct {
	mu          sync.Mutex
	closed      bool
	connections map[*trackedConn]struct{}
	dial        func(context.Context, string, string) (net.Conn, error)
}

type trackedConn struct {
	net.Conn
	release func()
}

func (connection *trackedConn) Close() error {
	err := connection.Conn.Close()
	connection.release()
	return err
}

func newConnectionTracker(dial func(context.Context, string, string) (net.Conn, error)) *connectionTracker {
	return &connectionTracker{
		connections: make(map[*trackedConn]struct{}),
		dial:        dial,
	}
}

func (tracker *connectionTracker) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	connection, err := tracker.dial(ctx, network, address)
	if err != nil {
		return nil, err
	}

	var tracked *trackedConn
	tracked = &trackedConn{
		Conn: connection,
		release: func() {
			tracker.mu.Lock()
			delete(tracker.connections, tracked)
			tracker.mu.Unlock()
		},
	}
	tracker.mu.Lock()
	if tracker.closed {
		tracker.mu.Unlock()
		_ = connection.Close()
		return nil, context.Canceled
	}
	tracker.connections[tracked] = struct{}{}
	tracker.mu.Unlock()
	return tracked, nil
}

func (tracker *connectionTracker) closeAll() {
	tracker.mu.Lock()
	tracker.closed = true
	connections := make([]*trackedConn, 0, len(tracker.connections))
	for connection := range tracker.connections {
		connections = append(connections, connection)
	}
	tracker.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}

type AuthInfo struct {
	LoginDomain string `json:"loginDomain"`
	AuthType    string `json:"authType"`
	AuthName    string `json:"authName"`
	LoginURL    string `json:"loginUrl"`
}

type LoginOptions struct {
	DeviceID   string
	Cookies    []Cookie
	TOTPSecret string
}

type LoginResult struct {
	Username string
	SID      string
	Cookies  []Cookie
}

type LoginMethod interface {
	AuthType() string
	LoginDomain() string
	login(*Session, AuthInfo) error
}

func (s *Session) randSdpId(n ...int) string {
	length := 8
	if len(n) > 0 {
		length = n[0]
	}
	hexes := make([]byte, length)
	for i := 0; i < length; i++ {
		hexes[i] = "0123456789abcdef"[mathrand.Intn(16)]
	}
	return string(hexes)
}

func (s *Session) withGraphCheckCode(process func(string) (int, error), graphCodeFile string) error {
	graphCheckCodeEnable, err := process("")
	if err != nil {
		return err
	}

	for attempt := 1; graphCheckCodeEnable == 1 && attempt <= maxAttempts; attempt++ {
		if attempt > 1 {
			log.Printf("Captcha attempt %d/%d", attempt, maxAttempts)
		}

		imgData, err := s.checkCode()
		if err != nil {
			return err
		}

		_, _, err = s.authConfig(false, true)
		if err != nil {
			return err
		}

		var graphCheckCode string
		if graphCodeFile != "" {
			if writeErr := os.WriteFile(graphCodeFile, imgData, 0644); writeErr != nil {
				log.Printf("Warning: failed to write graph code image to %s: %v", graphCodeFile, writeErr)
			} else {
				log.Printf("Graph check code saved to %s", graphCodeFile)
			}

			log.Print("Please enter the graph check code JSON: ")
			_, err = fmt.Scanln(&graphCheckCode)
			if err != nil {
				return err
			}
		} else {
			graphCheckCode, err = serveCaptchaInBrowser(imgData, 5*time.Minute)
			if err != nil {
				return fmt.Errorf("failed to get captcha input: %w", err)
			}
		}

		log.DebugPrintf("graphCheckCode submitted: %s", graphCheckCode)

		graphCheckCodeEnable, err = process(graphCheckCode)
		if err != nil {
			return err
		}

		if graphCheckCodeEnable == 0 {
			return nil
		}

		log.Printf("Captcha verification failed (attempt %d/%d), retrying with new captcha...", attempt, maxAttempts)
	}

	if graphCheckCodeEnable != 0 {
		return fmt.Errorf("captcha verification failed after %d attempts", maxAttempts)
	}
	return nil
}

func (s *Session) GetAuthInfoList() ([]AuthInfo, error) {
	_, list, err := s.authConfig(false, true)
	return list, err
}

func (s *Session) continueAuth(step authStep) error {
	for attempt := 0; attempt < maxAuthSteps; attempt++ {
		log.DebugPrintf("Continue authentication: service=%s smsMode=%d", step.Service, step.SMSMode)

		var err error
		switch step.Service {
		case "":
			return nil
		case "auth/authCheck":
			step, err = s.authCheck()
		case "auth/sms":
			step, err = s.completeSMS(step)
		case "auth/customSms":
			step, err = s.completeCustomSMS()
		case "auth/totp":
			step, err = s.completeTOTP()
		case "auth/radius":
			step, err = s.completeRadius("auth/token")
		case "auth/challenge":
			step, err = s.completeRadius("auth/challenge")
		case "auth/accessCheck":
			step, err = s.accessCheck()
		case "auth/preEnhancedAuth", "auth/enhancedConfirm", "auth/enhancedDone":
			step, err = s.completeEnhancedAuth(step)
		case "auth/bindAuthDevice":
			step, err = s.bindAuthDevice(step)
		case "auth/token":
			return fmt.Errorf("token authentication type is missing")
		default:
			return fmt.Errorf("unsupported next authentication service: %s", step.Service)
		}
		if err != nil {
			return err
		}
	}

	return fmt.Errorf("authentication chain exceeded %d steps", maxAuthSteps)
}

func (s *Session) completeSMS(step authStep) (authStep, error) {
	switch step.SMSMode {
	case smsWithAuthID:
		// HITSZ-style gateways refresh the ticket-bearing auth config before
		// querying the phone number and sending the SMS.
		if _, _, err := s.authConfig(true, true); err != nil {
			return authStep{}, err
		}
	case smsWithoutAuthID:
		// SARI-style gateways refresh auth config after sending the SMS.
	default:
		return authStep{}, fmt.Errorf("unknown SMS authentication mode")
	}

	phoneNumbers, err := s.phoneNumber(step.AuthID)
	if err != nil {
		log.Printf("Warning: failed to get phone number: %v", err)
	} else if len(phoneNumbers) > 0 {
		log.Printf("Phone number: %s", strings.Join(phoneNumbers, ", "))
	}

	if err := s.authSms(step); err != nil {
		return authStep{}, err
	}

	if step.SMSMode == smsWithoutAuthID {
		if _, _, err := s.authConfig(true, true); err != nil {
			return authStep{}, err
		}
	}

	return s.smsCheckCode(step)
}

func (s *Session) Login(method LoginMethod, opts LoginOptions) (LoginResult, error) {
	sid := ""
	if len(opts.Cookies) > 0 {
		for _, cookie := range opts.Cookies {
			if cookie.Host == s.baseHost && cookie.Scheme == "https" && cookie.Name == "sid" {
				sid = cookie.Value
			}

			c := &http.Cookie{
				Name:  cookie.Name,
				Value: cookie.Value,
			}
			s.client.Jar.SetCookies(&url.URL{Host: cookie.Host, Scheme: cookie.Scheme}, []*http.Cookie{c})
		}
	}

	s.deviceID = opts.DeviceID
	s.totpSecret = opts.TOTPSecret
	s.env = base64.StdEncoding.EncodeToString([]byte(`{"deviceId":"` + opts.DeviceID + `"}`))

	isLogin, authInfoList, err := s.authConfig(false, true)
	if err != nil {
		return LoginResult{}, err
	}
	if isLogin == 1 {
		log.Println("Already logged in")
		username, err := s.onlineInfo()
		if err != nil {
			return LoginResult{}, err
		}
		return LoginResult{
			Username: username,
			SID:      sessionSID(s),
			Cookies:  sessionCookies(s),
		}, nil
	}

	if method == nil {
		return LoginResult{}, ErrSessionInvalid
	}
	var foundAuthInfo *AuthInfo
	for _, authInfo := range authInfoList {
		if authInfo.AuthType == method.AuthType() && authInfo.LoginDomain == method.LoginDomain() {
			foundAuthInfo = &authInfo
			break
		}
	}
	if foundAuthInfo == nil {
		log.Printf("Available authentication methods: %+v", authInfoList)
		return LoginResult{}, fmt.Errorf("auth type/login domain combination not found: auth type: %s, login domain: %s", method.AuthType(), method.LoginDomain())
	}

	log.Printf("Starting login with auth type: %s, login domain: %s", method.AuthType(), method.LoginDomain())
	err = method.login(s, *foundAuthInfo)
	if err != nil {
		return LoginResult{}, err
	}

	err = s.reportEnv()
	if err != nil {
		return LoginResult{}, err
	}

	err = s.continueAuth(authStep{Service: "auth/authCheck"})
	if err != nil {
		return LoginResult{}, err
	}

	username, err := s.onlineInfo()
	if err != nil {
		return LoginResult{}, err
	}

	cookies := make([]Cookie, 0)
	for _, cookie := range s.client.Jar.Cookies(&url.URL{Host: s.baseHost, Scheme: "https"}) {
		if cookie.Name == "sid" {
			sid = cookie.Value
		}

		cookies = append(cookies, Cookie{
			Host:   s.baseHost,
			Scheme: "https",
			Name:   cookie.Name,
			Value:  cookie.Value,
		})
	}

	return LoginResult{
		Username: username,
		SID:      sid,
		Cookies:  cookies,
	}, nil
}

func sessionCookies(session *Session) []Cookie {
	endpoint := &url.URL{Host: session.baseHost, Scheme: "https"}
	cookies := session.client.Jar.Cookies(endpoint)
	result := make([]Cookie, 0, len(cookies))
	for _, cookie := range cookies {
		result = append(result, Cookie{
			Host:   session.baseHost,
			Scheme: "https",
			Name:   cookie.Name,
			Value:  cookie.Value,
		})
	}
	return result
}

func sessionSID(session *Session) string {
	for _, cookie := range sessionCookies(session) {
		if cookie.Name == "sid" {
			return cookie.Value
		}
	}
	return ""
}
