package auth

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
)

// InteractivePrompt is a single safe-to-display step in an aTrust login. It
// deliberately omits cookies, tokens, device identifiers, and submitted
// credentials. Callers use the matching InteractiveFlow method to continue.
type InteractivePrompt struct {
	State         string     `json:"state"`
	Message       string     `json:"message"`
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

type interactiveState string

const (
	interactiveNew                 interactiveState = "new"
	interactiveAwaitingMethod      interactiveState = "awaitingMethod"
	interactiveAwaitingCredentials interactiveState = "awaitingCredentials"
	interactiveAwaitingPhone       interactiveState = "awaitingPhone"
	interactiveAwaitingSMS         interactiveState = "awaitingSms"
	interactiveAwaitingCaptcha     interactiveState = "awaitingCaptcha"
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

	session  *Session
	deviceID string
	state    interactiveState
	methods  []AuthInfo
	selected *AuthInfo

	username string
	password string
	phone    string
	smsCode  string

	pendingStep authStep
	primarySMS  bool
	captcha     []byte
	purpose     captchaPurpose
	result      *InteractiveResult
	cancelled   bool
}

func NewInteractiveFlow(server string, dialContext ...func(context.Context, string, string) (net.Conn, error)) (*InteractiveFlow, error) {
	deviceID, err := randomDeviceID()
	if err != nil {
		return nil, fmt.Errorf("generate device id: %w", err)
	}
	return &InteractiveFlow{
		session:  NewSession(server, dialContext...),
		deviceID: deviceID,
		state:    interactiveNew,
	}, nil
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
		Message:     "Choose an authentication method",
		AuthMethods: append([]AuthInfo(nil), f.methods...),
	}, nil
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

// PendingCaptchaImage returns a defensive copy. The image is cleared when the
// challenge is submitted, cancelled, or replaced by another challenge.
func (f *InteractiveFlow) PendingCaptchaImage() ([]byte, error) {
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
	f.mu.Lock()
	defer f.mu.Unlock()
	f.cancelled = true
	f.state = interactiveCancelled
	f.clearSensitiveState()
	f.session.client.CloseIdleConnections()
}

func (f *InteractiveFlow) ClearResult() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.result = nil
}

func (f *InteractiveFlow) Result() (InteractiveResult, bool) {
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

func sessionCookies(session *Session) []Cookie {
	endpoint := &url.URL{Host: session.baseHost, Scheme: "https"}
	cookies := session.client.Jar.Cookies(endpoint)
	result := make([]Cookie, 0, len(cookies))
	for _, cookie := range cookies {
		result = append(result, Cookie{Host: session.baseHost, Scheme: "https", Name: cookie.Name, Value: cookie.Value})
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

func (f *InteractiveFlow) clearCredentials() {
	f.password = ""
	f.smsCode = ""
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
