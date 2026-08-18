package auth

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"sync/atomic"
)

// InteractivePrompt is a single safe-to-display step in an aTrust login. It
// deliberately omits cookies, tokens, device identifiers, and submitted
// credentials. Callers use the matching InteractiveFlow method to continue.
type InteractivePrompt struct {
	State         string     `json:"state"`
	Code          string     `json:"code,omitempty"`
	Message       string     `json:"message"`
	ChallengeKind string     `json:"challengeKind,omitempty"`
	AuthMethods   []AuthInfo `json:"authMethods,omitempty"`
	PhoneNumbers  []string   `json:"phoneNumbers,omitempty"`
	CaptchaWidth  int        `json:"captchaWidth,omitempty"`
	CaptchaHeight int        `json:"captchaHeight,omitempty"`
}

// InteractiveResult remains in process memory. The bridge consumes it to
// prepare a future tunnel and must never serialize it into an event or file.
type InteractiveResult struct {
	Username     string
	SID          string
	AuthData     []byte
	ResourceData []byte
}

// InteractiveFlowOptions configures caller-owned authentication identity and
// transport verification. Android callers must set StrictTLS so the system CA
// pool and hostname verification run before application-layer anti-MITM checks.
type InteractiveFlowOptions struct {
	DeviceID  string
	StrictTLS bool
}

type interactiveState string

const (
	interactiveNew                 interactiveState = "new"
	interactiveAwaitingMethod      interactiveState = "awaitingMethod"
	interactiveAwaitingCredentials interactiveState = "awaitingCredentials"
	interactiveAwaitingPhone       interactiveState = "awaitingPhone"
	interactiveAwaitingSMS         interactiveState = "awaitingSms"
	interactiveAwaitingCaptcha     interactiveState = "awaitingCaptcha"
	interactiveAwaitingToken       interactiveState = "awaitingToken"
	interactiveAuthenticated       interactiveState = "authenticated"
	interactiveCancelled           interactiveState = "cancelled"
)

type captchaPurpose uint8

const (
	captchaForPassword captchaPurpose = iota + 1
	captchaForPrimarySMSSend
	captchaForPrimarySMSCheck
)

// InteractiveFlow replaces the CLI's stdin, temporary-file, and browser
// interactions. It is intentionally single-session; callers must serialize
// method calls. Cancel is safe to call repeatedly.
type InteractiveFlow struct {
	mu sync.Mutex

	session        *Session
	deviceID       string
	deviceIDLocked bool
	state          interactiveState
	methods        []AuthInfo
	selected       *AuthInfo

	username string
	password string
	phone    string
	smsCode  string

	pendingStep authStep
	primarySMS  bool
	captcha     []byte
	purpose     captchaPurpose
	result      *InteractiveResult
	cancelOnce  sync.Once
	cancelled   atomic.Bool
}

func NewInteractiveFlow(server string, dialContext ...func(context.Context, string, string) (net.Conn, error)) (*InteractiveFlow, error) {
	deviceID, err := randomDeviceID()
	if err != nil {
		return nil, fmt.Errorf("generate device id: %w", err)
	}
	return newInteractiveFlow(server, deviceID, false, true, dialContext...), nil
}

// NewInteractiveFlowWithDeviceID creates an interactive flow whose device
// identity is owned by the caller. Restored snapshots cannot replace it.
func NewInteractiveFlowWithDeviceID(server, deviceID string, dialContext ...func(context.Context, string, string) (net.Conn, error)) (*InteractiveFlow, error) {
	return NewInteractiveFlowWithOptions(server, InteractiveFlowOptions{
		DeviceID:  deviceID,
		StrictTLS: true,
	}, dialContext...)
}

// NewInteractiveFlowWithOptions creates a caller-configured interactive flow.
// It keeps the legacy constructors intact while making Android's stable device
// identity and strict TLS policy explicit at the bridge boundary.
func NewInteractiveFlowWithOptions(server string, options InteractiveFlowOptions, dialContext ...func(context.Context, string, string) (net.Conn, error)) (*InteractiveFlow, error) {
	deviceID := options.DeviceID
	if len(deviceID) != 32 {
		return nil, fmt.Errorf("device id must contain 32 hexadecimal characters")
	}
	if _, err := hex.DecodeString(deviceID); err != nil {
		return nil, fmt.Errorf("device id is not hexadecimal: %w", err)
	}
	return newInteractiveFlow(server, deviceID, true, options.StrictTLS, dialContext...), nil
}

func newInteractiveFlow(server, deviceID string, locked, strictTLS bool, dialContext ...func(context.Context, string, string) (net.Conn, error)) *InteractiveFlow {
	var tlsConfig *tls.Config
	if !strictTLS {
		tlsConfig = &tls.Config{InsecureSkipVerify: true} // #nosec G402 -- opt-in compatibility for non-Android callers.
	}
	return &InteractiveFlow{
		session:        newSession(server, tlsConfig, dialContext...),
		deviceID:       deviceID,
		deviceIDLocked: locked,
		state:          interactiveNew,
	}
}

func randomDeviceID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// Begin retrieves the server's advertised methods without authenticating.
func (f *InteractiveFlow) Begin() (InteractivePrompt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != interactiveNew {
		return InteractivePrompt{}, fmt.Errorf("authentication flow already started")
	}

	return f.begin("")
}

func (f *InteractiveFlow) begin(code string) (InteractivePrompt, error) {
	f.session.deviceID = f.deviceID
	f.session.env = base64.StdEncoding.EncodeToString([]byte(`{"deviceId":"` + f.deviceID + `"}`))
	_, methods, err := f.session.authConfig(false, true)
	if err != nil {
		return InteractivePrompt{}, err
	}
	if len(methods) == 0 {
		return InteractivePrompt{}, fmt.Errorf("server did not advertise a supported authentication method")
	}
	f.methods = append([]AuthInfo(nil), methods...)
	f.state = interactiveAwaitingMethod
	return InteractivePrompt{
		State:       string(f.state),
		Code:        code,
		Message:     "Choose an authentication method",
		AuthMethods: append([]AuthInfo(nil), f.methods...),
	}, nil
}

// Resume validates previously persisted authentication data with the server
// and rebuilds the same in-memory result produced by an interactive login.
// Only cookies and the exact device ID are restored; username, SID, and
// resources are fetched again after the server confirms that the session is
// still authenticated.
func (f *InteractiveFlow) Resume(authData []byte) (InteractivePrompt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != interactiveNew {
		return InteractivePrompt{}, fmt.Errorf("authentication flow already started")
	}

	var clientAuthData ClientAuthData
	if err := json.Unmarshal(authData, &clientAuthData); err != nil {
		return InteractivePrompt{}, fmt.Errorf("decode authentication session: %w", err)
	}
	if clientAuthData.DeviceID == "" || len(clientAuthData.Cookies) == 0 {
		return InteractivePrompt{}, fmt.Errorf("authentication session is incomplete")
	}
	hasSID := false
	for _, cookie := range clientAuthData.Cookies {
		if cookie.Host != f.session.baseHost || cookie.Scheme != "https" || cookie.Name == "" || cookie.Value == "" {
			return InteractivePrompt{}, fmt.Errorf("authentication session contains an invalid cookie")
		}
		if cookie.Name == "sid" {
			hasSID = true
		}
	}
	if !hasSID {
		return InteractivePrompt{}, fmt.Errorf("authentication session does not contain sid")
	}

	if !f.deviceIDLocked {
		f.deviceID = clientAuthData.DeviceID
	}
	loginResult, err := f.session.Login(nil, LoginOptions{
		DeviceID: f.deviceID,
		Cookies:  append([]Cookie(nil), clientAuthData.Cookies...),
	})
	if err != nil {
		if errors.Is(err, ErrSessionInvalid) {
			// A rejected SID is not evidence that the authenticated client
			// context is useless. Session.Login has already restored the
			// persisted cookies into this Session's jar, and the server may use
			// them together with the stable device identity during password
			// reauthentication. Keep that context until an explicit cancellation
			// or account switch instead of replacing it with a blank Session.
			f.resetForReauthentication()
			return f.begin("sessionExpired")
		}
		return InteractivePrompt{}, err
	}
	resourceData, err := f.session.ClientResource()
	if err != nil {
		return InteractivePrompt{}, err
	}
	currentAuthData, err := json.Marshal(ClientAuthData{
		Cookies:  sessionCookies(f.session),
		DeviceID: f.deviceID,
	})
	if err != nil {
		return InteractivePrompt{}, err
	}
	sid := sessionSID(f.session)
	if sid == "" {
		return InteractivePrompt{}, fmt.Errorf("restored authentication session does not contain sid")
	}
	f.result = &InteractiveResult{
		Username:     loginResult.Username,
		SID:          sid,
		AuthData:     currentAuthData,
		ResourceData: resourceData,
	}
	f.clearCredentials()
	f.state = interactiveAuthenticated
	return InteractivePrompt{State: string(f.state), Message: "Authentication session restored"}, nil
}

func (f *InteractiveFlow) SelectMethod(authType, loginDomain string) (InteractivePrompt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != interactiveAwaitingMethod {
		return InteractivePrompt{}, fmt.Errorf("authentication method is not expected")
	}
	for index := range f.methods {
		method := &f.methods[index]
		if method.AuthType == authType && method.LoginDomain == loginDomain {
			f.selected = method
			switch method.AuthType {
			case "auth/psw":
				f.state = interactiveAwaitingCredentials
				return InteractivePrompt{State: string(f.state), Message: "Enter your account and password"}, nil
			case "auth/smsCheckCode":
				f.state = interactiveAwaitingPhone
				return InteractivePrompt{State: string(f.state), Message: "Enter the phone number registered for this method"}, nil
			default:
				return InteractivePrompt{}, fmt.Errorf("unsupported authentication method: %s", method.AuthType)
			}
		}
	}
	return InteractivePrompt{}, fmt.Errorf("selected authentication method was not advertised by the server")
}

func (f *InteractiveFlow) SubmitCredentials(username, password string) (InteractivePrompt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != interactiveAwaitingCredentials || f.selected == nil || f.selected.AuthType != "auth/psw" {
		return InteractivePrompt{}, fmt.Errorf("account credentials are not expected")
	}
	if username == "" || password == "" {
		return InteractivePrompt{}, fmt.Errorf("account and password are required")
	}
	f.username = username
	f.password = password
	return f.passwordAttempt("")
}

func (f *InteractiveFlow) SubmitPhone(phone string) (InteractivePrompt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != interactiveAwaitingPhone || f.selected == nil || f.selected.AuthType != "auth/smsCheckCode" {
		return InteractivePrompt{}, fmt.Errorf("phone number is not expected")
	}
	if phone == "" {
		return InteractivePrompt{}, fmt.Errorf("phone number is required")
	}
	f.phone = phone
	f.primarySMS = true
	return f.primarySMSSend("")
}

func (f *InteractiveFlow) SubmitSMSCode(code string) (InteractivePrompt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != interactiveAwaitingSMS {
		return InteractivePrompt{}, fmt.Errorf("SMS code is not expected")
	}
	if code == "" {
		return InteractivePrompt{}, fmt.Errorf("SMS code is required")
	}
	if f.primarySMS {
		f.smsCode = code
		return f.primarySMSCheck("")
	}

	var (
		step authStep
		err  error
	)
	if f.pendingStep.Service == "auth/customSms" {
		step, err = f.session.customSMSCheckCode(code, false)
	} else {
		step, err = f.session.secondarySMSCheckCodeImpl(f.pendingStep, code, false)
	}
	if err != nil {
		return InteractivePrompt{}, err
	}
	return f.advance(step)
}

// SubmitToken continues a server-selected TOTP, RADIUS, token, or challenge
// step. The token remains in memory only for the duration of the request.
func (f *InteractiveFlow) SubmitToken(token string) (InteractivePrompt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != interactiveAwaitingToken {
		return InteractivePrompt{}, fmt.Errorf("authentication token is not expected")
	}
	if token == "" {
		return InteractivePrompt{}, fmt.Errorf("authentication token is required")
	}

	token, skipSecondaryAuth := parseTokenInput(token)
	payload := map[string]interface{}{"skipSecondaryAuth": skipSecondaryAuth}
	var (
		step authStep
		err  error
	)
	switch f.pendingStep.Service {
	case "auth/totp":
		payload["action"] = "auth"
		payload["totpToken"] = token
		payload["isPrevEffect"] = false
		f.session.addUsername(payload)
		step, err = f.session.submitToken(payload)
	case "auth/radius", "auth/token":
		payload["radiusToken"] = token
		f.session.addUsername(payload)
		step, err = f.session.submitTokenAt("auth/token", payload)
	case "auth/challenge":
		payload["radiusToken"] = token
		f.session.addUsername(payload)
		step, err = f.session.submitTokenAt("auth/challenge", payload)
	default:
		return InteractivePrompt{}, fmt.Errorf("unsupported authentication token service: %s", f.pendingStep.Service)
	}
	if err != nil {
		return InteractivePrompt{}, err
	}
	return f.advance(step)
}

// PendingCaptchaImage returns a defensive copy. The image is cleared when the
// challenge is submitted, cancelled, or replaced by another challenge.
func (f *InteractiveFlow) PendingCaptchaImage() ([]byte, error) {
	if f.cancelled.Load() {
		return nil, fmt.Errorf("captcha image is not available")
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != interactiveAwaitingCaptcha || len(f.captcha) == 0 {
		return nil, fmt.Errorf("captcha image is not available")
	}
	return append([]byte(nil), f.captcha...), nil
}

func (f *InteractiveFlow) SubmitCaptcha(raw string) (InteractivePrompt, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.state != interactiveAwaitingCaptcha || len(f.captcha) == 0 {
		return InteractivePrompt{}, fmt.Errorf("captcha is not expected")
	}
	code, err := canonicalizeGraphCheckCode(raw, f.captcha)
	if err != nil {
		return InteractivePrompt{}, err
	}
	purpose := f.purpose
	f.captcha = nil
	f.purpose = 0
	switch purpose {
	case captchaForPassword:
		return f.passwordAttempt(code)
	case captchaForPrimarySMSSend:
		return f.primarySMSSend(code)
	case captchaForPrimarySMSCheck:
		return f.primarySMSCheck(code)
	default:
		return InteractivePrompt{}, fmt.Errorf("captcha continuation is unavailable")
	}
}

func (f *InteractiveFlow) Cancel() {
	// A network operation holds f.mu while it uses the credential fields. Do
	// not wait for that operation here: cancel its request context first, then
	// scrub state as soon as the now-interrupted operation releases the lock.
	f.cancelled.Store(true)
	f.session.cancel()
	f.cancelOnce.Do(func() {
		go f.finalizeCancellation()
	})
}

func (f *InteractiveFlow) finalizeCancellation() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.state = interactiveCancelled
	f.clearSensitiveState()
}

func (f *InteractiveFlow) ClearResult() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.result = nil
}

func (f *InteractiveFlow) Result() (InteractiveResult, bool) {
	if f.cancelled.Load() {
		return InteractiveResult{}, false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.result == nil {
		return InteractiveResult{}, false
	}
	return InteractiveResult{
		Username:     f.result.Username,
		SID:          f.result.SID,
		AuthData:     append([]byte(nil), f.result.AuthData...),
		ResourceData: append([]byte(nil), f.result.ResourceData...),
	}, true
}

func (f *InteractiveFlow) passwordAttempt(graphCheckCode string) (InteractivePrompt, error) {
	enabled, err := f.session.pswImpl(f.username, f.password, f.selected.LoginDomain, graphCheckCode)
	if err != nil {
		if errors.Is(err, ErrCredentialsRejected) {
			f.clearCredentials()
			f.state = interactiveAwaitingCredentials
			return InteractivePrompt{
				State:   string(f.state),
				Code:    "credentialsRejected",
				Message: "The saved account credentials were rejected",
			}, nil
		}
		return InteractivePrompt{}, err
	}
	if enabled == 1 {
		return f.requireCaptcha(captchaForPassword)
	}
	return f.finishPrimaryAuthentication()
}

func (f *InteractiveFlow) primarySMSSend(graphCheckCode string) (InteractivePrompt, error) {
	enabled, err := f.session.sendSms(f.phone, f.selected.LoginDomain, graphCheckCode)
	if err != nil {
		return InteractivePrompt{}, err
	}
	if enabled == 1 {
		return f.requireCaptcha(captchaForPrimarySMSSend)
	}
	f.state = interactiveAwaitingSMS
	return InteractivePrompt{State: string(f.state), Message: "Enter the SMS verification code"}, nil
}

func (f *InteractiveFlow) primarySMSCheck(graphCheckCode string) (InteractivePrompt, error) {
	enabled, err := f.session.smsCheckCodeImpl(f.smsCode, f.phone, f.selected.LoginDomain, graphCheckCode)
	if err != nil {
		return InteractivePrompt{}, err
	}
	if enabled == 1 {
		return f.requireCaptcha(captchaForPrimarySMSCheck)
	}
	return f.finishPrimaryAuthentication()
}

func (f *InteractiveFlow) requireCaptcha(purpose captchaPurpose) (InteractivePrompt, error) {
	imageData, err := f.session.checkCode()
	if err != nil {
		return InteractivePrompt{}, err
	}
	if _, _, err = f.session.authConfig(false, true); err != nil {
		return InteractivePrompt{}, err
	}
	width, height, err := decodeImageSize(imageData)
	if err != nil {
		return InteractivePrompt{}, err
	}
	f.captcha = append([]byte(nil), imageData...)
	f.purpose = purpose
	f.state = interactiveAwaitingCaptcha
	return InteractivePrompt{
		State:         string(f.state),
		Message:       "Complete the graphical verification",
		CaptchaWidth:  width,
		CaptchaHeight: height,
	}, nil
}

func (f *InteractiveFlow) finishPrimaryAuthentication() (InteractivePrompt, error) {
	if err := f.session.reportEnv(); err != nil {
		return InteractivePrompt{}, err
	}
	return f.advance(authStep{Service: "auth/authCheck"})
}

func (f *InteractiveFlow) advance(step authStep) (InteractivePrompt, error) {
	for attempts := 0; attempts < maxAuthSteps; attempts++ {
		switch step.Service {
		case "":
			return f.complete()
		case "auth/authCheck":
			next, err := f.session.authCheck()
			if err != nil {
				return InteractivePrompt{}, err
			}
			step = next
		case "auth/sms":
			if step.SMSMode == smsWithAuthID {
				if _, _, err := f.session.authConfig(true, true); err != nil {
					return InteractivePrompt{}, err
				}
			}
			phones, _ := f.session.phoneNumber(step.AuthID)
			if err := f.session.authSms(step); err != nil {
				return InteractivePrompt{}, err
			}
			if step.SMSMode == smsWithoutAuthID {
				if _, _, err := f.session.authConfig(true, true); err != nil {
					return InteractivePrompt{}, err
				}
			}
			f.pendingStep = step
			f.primarySMS = false
			f.state = interactiveAwaitingSMS
			return InteractivePrompt{State: string(f.state), Message: "Enter the SMS verification code", PhoneNumbers: phones}, nil
		case "auth/customSms":
			if err := f.session.sendCustomSMS(); err != nil {
				return InteractivePrompt{}, err
			}
			f.pendingStep = step
			f.primarySMS = false
			f.state = interactiveAwaitingSMS
			return InteractivePrompt{State: string(f.state), Message: "Enter the SMS verification code"}, nil
		case "auth/totp", "auth/radius", "auth/challenge", "auth/token":
			f.pendingStep = step
			f.state = interactiveAwaitingToken
			return InteractivePrompt{
				State:         string(f.state),
				Message:       "Enter the authentication token requested by the server",
				ChallengeKind: step.Service,
			}, nil
		case "auth/accessCheck":
			next, err := f.session.accessCheck()
			if err != nil {
				return InteractivePrompt{}, err
			}
			step = next
		case "auth/preEnhancedAuth", "auth/enhancedConfirm", "auth/enhancedDone":
			next, err := f.session.completeEnhancedAuth(step)
			if err != nil {
				return InteractivePrompt{}, err
			}
			step = next
		case "auth/bindAuthDevice":
			next, err := f.session.bindAuthDevice(step)
			if err != nil {
				return InteractivePrompt{}, err
			}
			step = next
		default:
			return InteractivePrompt{}, fmt.Errorf("unsupported next authentication service: %s", step.Service)
		}
	}
	return InteractivePrompt{}, fmt.Errorf("authentication chain exceeded %d steps", maxAuthSteps)
}

func (f *InteractiveFlow) complete() (InteractivePrompt, error) {
	username, err := f.session.onlineInfo()
	if err != nil {
		return InteractivePrompt{}, err
	}
	resourceData, err := f.session.ClientResource()
	if err != nil {
		return InteractivePrompt{}, err
	}
	authData, err := json.Marshal(ClientAuthData{
		Cookies:  sessionCookies(f.session),
		DeviceID: f.deviceID,
	})
	if err != nil {
		return InteractivePrompt{}, err
	}
	f.result = &InteractiveResult{
		Username:     username,
		SID:          sessionSID(f.session),
		AuthData:     authData,
		ResourceData: resourceData,
	}
	f.clearCredentials()
	f.state = interactiveAuthenticated
	return InteractivePrompt{State: string(f.state), Message: "Authentication completed"}, nil
}

func (f *InteractiveFlow) clearCredentials() {
	f.username = ""
	f.password = ""
	f.smsCode = ""
}

// resetForReauthentication clears only ephemeral interactive input while
// preserving the Session, its cookie jar, and the caller-owned device ID.
// It is used after a restored SID expires, before the caller selects a fresh
// server-advertised authentication method.
func (f *InteractiveFlow) resetForReauthentication() {
	f.clearCredentials()
	f.phone = ""
	f.captcha = nil
	f.purpose = 0
	f.pendingStep = authStep{}
	f.primarySMS = false
	f.methods = nil
	f.selected = nil
	f.result = nil
	f.state = interactiveNew
}

func (f *InteractiveFlow) clearSensitiveState() {
	f.clearCredentials()
	f.phone = ""
	f.captcha = nil
	f.purpose = 0
	f.result = nil
	f.pendingStep = authStep{}
	f.primarySMS = false
}

// Keep net/http imported in this file's API surface check. NewSession owns the
// HTTP client and this declaration protects against accidental replacement by a
// browser or file-backed transport.
var _ = http.MethodPost
