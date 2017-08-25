package oauth2

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/flimzy/diff"
	"github.com/flimzy/flashback-server2/providers/testprovider"
	"github.com/flimzy/kivik/errors"
)

func TestOAuth2(t *testing.T) {
	type oaTest struct {
		name   string
		req    *http.Request
		next   http.Handler
		status int
	}
	testProvider := testprovider.New()
	tests := []oaTest{
		{
			name:   "Get",
			req:    httptest.NewRequest("GET", "/_session", nil),
			status: http.StatusNotFound,
		},
		{
			name:   "PostRoot",
			req:    httptest.NewRequest("POST", "/", nil),
			status: http.StatusNotFound,
		},
		{
			name:   "NoContentType",
			req:    httptest.NewRequest("POST", "/_session", nil),
			status: http.StatusNotFound,
		},
		{
			name: "PostImage",
			req: func() *http.Request {
				r := httptest.NewRequest("POST", "/_session", nil)
				r.Header.Set("Content-Type", "image/jpeg")
				return r
			}(),
			status: http.StatusNotFound,
		},
		{
			name: "JSONNoBody",
			req: func() *http.Request {
				r := httptest.NewRequest("POST", "/_session", nil)
				r.Header.Set("Content-Type", "application/json")
				return r
			}(),
			status: http.StatusBadRequest,
		},
		{
			name: "InvalidJSON",
			req: func() *http.Request {
				r := httptest.NewRequest("POST", "/_session", strings.NewReader("yooooo"))
				r.Header.Set("Content-Type", "application/json")
				return r
			}(),
			status: http.StatusBadRequest,
		},
		{
			name: "InvalidForm",
			req: func() *http.Request {
				r := httptest.NewRequest("POST", "/_session", strings.NewReader("foo%xxx"))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return r
			}(),
			status: http.StatusBadRequest,
		},
		{
			name: "FormNoBody",
			req: func() *http.Request {
				r := httptest.NewRequest("POST", "/_session", nil)
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return r
			}(),
			status: http.StatusBadRequest,
		},
		{
			name: "JSONBadAuthProvider",
			req: func() *http.Request {
				r := httptest.NewRequest("POST", "/_session", strings.NewReader(`{"provider":"yerMom","access_token":"goaway"}`))
				r.Header.Set("Content-Type", "application/json")
				return r
			}(),
			status: http.StatusBadRequest,
		},
		{
			name: "JSONBadCreds",
			req: func() *http.Request {
				r := httptest.NewRequest("POST", "/_session", strings.NewReader(`{"provider":"testprovider","access_token":"goaway"}`))
				r.Header.Set("Content-Type", "application/json")
				return r
			}(),
			status: http.StatusUnauthorized,
		},
		{
			name: "JSONGoodCreds",
			req: func() *http.Request {
				body := fmt.Sprintf(`{"provider":"testprovider","access_token":"%s"}`, testProvider.Token)
				r := httptest.NewRequest("POST", "/_session", strings.NewReader(body))
				r.Header.Set("Content-Type", "application/json")
				return r
			}(),
			status: http.StatusOK,
		},
		{
			name: "JSONGoodCredsBadRedir",
			req: func() *http.Request {
				body := fmt.Sprintf(`{"provider":"testprovider","access_token":"%s"}`, testProvider.Token)
				r := httptest.NewRequest("POST", "/_session?next=http%3A%2F%2Fbar.com%2Foink", strings.NewReader(body))
				r.Header.Set("Content-Type", "application/json")
				return r
			}(),
			status: http.StatusBadRequest,
		},
		{
			name: "JSONGoodCredsGoodRedir",
			req: func() *http.Request {
				body := fmt.Sprintf(`{"provider":"testprovider","access_token":"%s"}`, testProvider.Token)
				r := httptest.NewRequest("POST", "/_session?next=%2Foink", strings.NewReader(body))
				r.Header.Set("Content-Type", "application/json")
				return r
			}(),
			status: http.StatusFound,
		},
	}
	providers := map[string]Provider{
		"testprovider": testProvider,
	}
	mw := OAuth2(providers, "foo")
	for _, test := range tests {
		func(test oaTest) {
			t.Run(test.name, func(t *testing.T) {
				next := test.next
				if next == nil {
					next = http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusNotFound)
					})
				}
				w := httptest.NewRecorder()
				mw(next).ServeHTTP(w, test.req)
				res := w.Result()
				if res.StatusCode != test.status {
					t.Errorf("Unexpected status: %d %s", res.StatusCode, res.Status)
				}
			})
		}(test)
	}
}

func TestNewAuthRequest(t *testing.T) {
	type narTest struct {
		Name     string
		Provider *string
		Token    *string
		Expected *authRequest
		Error    string
	}
	tests := []narTest{
		{
			Name:     "Nothing",
			Expected: nil,
		},
		{
			Name:  "NoProvider",
			Token: func() *string { x := "bar"; return &x }(),
			Error: "No provider specified",
		},
		{
			Name:     "NoToken",
			Provider: func() *string { x := "bar"; return &x }(),
			Error:    "No access token provided",
		},
		{
			Name:     "Good",
			Token:    func() *string { x := "foo"; return &x }(),
			Provider: func() *string { x := "bar"; return &x }(),
			Expected: &authRequest{Provider: "bar", Token: "foo"},
		},
	}
	for _, test := range tests {
		func(test narTest) {
			t.Run(test.Name, func(t *testing.T) {
				result, err := newAuthRequest(test.Provider, test.Token)
				var msg string
				if err != nil {
					msg = err.Error()
				}
				if msg != test.Error {
					t.Errorf("Unexpected error: %s", msg)
				}
				if d := diff.Interface(test.Expected, result); d != nil {
					t.Error(d)
				}
			})
		}(test)
	}
}

type errorReader struct{}

var _ io.Reader = &errorReader{}

func (r *errorReader) Read(_ []byte) (int, error) {
	return 0, errors.New("errorReader")
}

func TestParseAuthRequest(t *testing.T) {
	type arTest struct {
		Name     string
		Request  *http.Request
		Expected *authRequest
		Error    string
		Status   int
		Remain   string
	}
	tests := []arTest{
		{
			Name: "BadReader",
			Request: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/_session", &errorReader{})
				req.Header.Set("Content-Type", "application/json")
				return req
			}(),
			Error:  "errorReader",
			Status: http.StatusInternalServerError,
		},
		{
			Name: "MissingFormBody",
			Request: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/_session", nil)
				_ = req.Body.Close()
				req.Body = nil
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			}(),
			Error:  "missing body",
			Status: http.StatusBadRequest,
		},
		{
			Name: "ZeroLengthBody",
			Request: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/_session", strings.NewReader(""))
				_ = req.Body.Close()
				req.Body = nil
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			}(),
			Error:  "missing body",
			Status: http.StatusBadRequest,
		},
		{
			Name:    "NoMediaType",
			Request: httptest.NewRequest(http.MethodPost, "/_session", nil),
			Status:  0, // No error; falls through
		},
		{
			Name: "OtherMediaType",
			Request: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/_session", &errorReader{})
				req.Header.Set("Content-Type", "image/jpeg")
				return req
			}(),
			Status: 0, // No error; falls through
		},
		{
			Name: "InvalidJSON",
			Request: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/_session", strings.NewReader("{invalid!!"))
				req.Header.Set("Content-Type", "application/json")
				return req
			}(),
			Error:  "invalid character 'i' looking for beginning of object key string",
			Status: http.StatusBadRequest,
		},
		{
			Name: "NonOAuth2JSON",
			Request: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/_session", strings.NewReader(`{"foo":"bar"}`))
				req.Header.Set("Content-Type", "application/json")
				return req
			}(),
			Remain: `{"foo":"bar"}`,
		},
		{
			Name: "ValidJSON",
			Request: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/_session", strings.NewReader(`{"provider":"foo","access_token":"bar"}`))
				req.Header.Set("Content-Type", "application/json")
				return req
			}(),
			Expected: &authRequest{Provider: "foo", Token: "bar"},
		},

		{
			Name: "InvalidForm",
			Request: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/_session", strings.NewReader("invalid%xx"))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			}(),
			Error:  `invalid URL escape "%xx"`,
			Status: http.StatusBadRequest,
		},
		{
			Name: "NonOAuth2Form",
			Request: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/_session", strings.NewReader("foo=bar&bar=baz"))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			}(),
			Remain: "foo=bar&bar=baz",
		},
		{
			Name: "ValidJSON",
			Request: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/_session", strings.NewReader("provider=foo&access_token=bar"))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			}(),
			Expected: &authRequest{Provider: "foo", Token: "bar"},
		},
	}
	for _, test := range tests {
		func(test arTest) {
			t.Run(test.Name, func(t *testing.T) {
				result, err := parseAuthRequest(test.Request)
				var msg string
				if err != nil {
					msg = err.Error()
				}
				if msg != test.Error {
					t.Errorf("Unexpected error: %s", msg)
				}
				if status := errors.StatusCode(err); status != test.Status {
					t.Errorf("Unexpected error status: %d", status)
				}
				if err != nil {
					return
				}
				if d := diff.Interface(test.Expected, result); d != nil {
					t.Error(d)
				}
				remain := &bytes.Buffer{}
				_, _ = remain.ReadFrom(test.Request.Body)
				_ = test.Request.Body.Close()
				if remain.String() != test.Remain {
					t.Errorf("Remaining body\nExpected: %s\n  Actual: %s", test.Remain, remain)
				}
			})
		}(test)
	}
}

func TestParseFormAuthRequest(t *testing.T) {
	type formTest struct {
		Name     string
		Request  *http.Request
		Error    string
		Status   int
		Expected *authRequest
		Parsed   bool
	}
	tests := []formTest{
		{
			Name: "InvalidForm",
			Request: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/_session", strings.NewReader(`invalid%xxx`))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			}(),
			Error:  `invalid URL escape "%xx"`,
			Status: http.StatusBadRequest,
		},
		{
			Name: "ValidForm",
			Request: func() *http.Request {
				req := httptest.NewRequest(http.MethodPost, "/_session", strings.NewReader(`provider=foo&access_token=bar`))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return req
			}(),
			Expected: &authRequest{Provider: "foo", Token: "bar"},
		},
	}
	for _, test := range tests {
		func(test formTest) {
			t.Run(test.Name, func(t *testing.T) {
				body, err := ioutil.ReadAll(test.Request.Body)
				_ = test.Request.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				provider, token, err := parseFormAuthRequest(body)
				var msg string
				if err != nil {
					msg = err.Error()
				}
				if msg != test.Error {
					t.Errorf("Unexpected error: %s", msg)
				}
				if status := errors.StatusCode(err); status != test.Status {
					t.Errorf("Unexpected error status: %d", status)
				}
				if err != nil {
					return
				}
				result, err := newAuthRequest(provider, token)
				if err != nil {
					t.Fatal(err)
				}
				if d := diff.Interface(test.Expected, result); d != nil {
					t.Error(d)
				}
			})
		}(test)
	}
}

func TestParseJSONAuthRequest(t *testing.T) {
	type jsonTest struct {
		Name     string
		Request  *http.Request
		Error    string
		Status   int
		Expected *authRequest
		Remain   string
	}
	tests := []jsonTest{
		{
			Name:    "InvalidJSON",
			Request: httptest.NewRequest(http.MethodPost, "/_session", strings.NewReader(`{invalid!!`)),
			Status:  http.StatusBadRequest,
			Error:   "invalid character 'i' looking for beginning of object key string",
		},
		{
			Name:    "Passthrough",
			Request: httptest.NewRequest(http.MethodPost, "/_session", strings.NewReader(`{"foo":"bar"}`)),
			Remain:  `{"foo":"bar"}`,
		},
		{
			Name:     "ValidJSON",
			Request:  httptest.NewRequest(http.MethodPost, "/_session", strings.NewReader(`{"provider":"foo","access_token":"bar"}`)),
			Expected: &authRequest{Provider: "foo", Token: "bar"},
		},
	}
	for _, test := range tests {
		func(test jsonTest) {
			t.Run(test.Name, func(t *testing.T) {
				body, err := ioutil.ReadAll(test.Request.Body)
				_ = test.Request.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				provider, token, err := parseJSONAuthRequest(body)
				var msg string
				if err != nil {
					msg = err.Error()
				}
				if msg != test.Error {
					t.Errorf("Unexpected error: %s", msg)
				}
				if status := errors.StatusCode(err); status != test.Status {
					t.Errorf("Unexpected error status: %d", status)
				}
				if err != nil {
					return
				}
				result, err := newAuthRequest(provider, token)
				if err != nil {
					t.Fatal(err)
				}
				if d := diff.Interface(test.Expected, result); d != nil {
					t.Error(d)
				}
			})
		}(test)
	}
}
