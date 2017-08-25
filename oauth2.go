package oauth2

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/flimzy/kivik"
	"github.com/flimzy/kivik/authdb"
	"github.com/flimzy/kivik/errors"
	"github.com/flimzy/log"
	"github.com/monoculum/formam"

	fb "github.com/FlashbackSRS/flashback-model"
)

func reportError(w http.ResponseWriter, err error) {
	if err != nil {
		status := kivik.StatusCode(err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		detail := map[string]string{
			"error":  strings.ToLower(http.StatusText(status)),
			"reason": err.Error(),
		}
		if e := json.NewEncoder(w).Encode(detail); e != nil {
			log.Printf("Failed to send error to client: %s", e)
		}
		fmt.Fprintf(w, "%d %s", status, err)
	}
}

// Provider is a copy of flashback-server2/providers.Provider
type Provider interface {
	GetUser(ctx context.Context, token string) (*fb.User, error)
}

// OAuth2 is middleware for OAuth2 authentication.
func OAuth2(providers map[string]Provider, secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/_session" {
				next.ServeHTTP(w, r)
				return
			}

			authReq, err := parseAuthRequest(r)
			if err != nil {
				reportError(w, err)
				return
			}
			if authReq == nil {
				next.ServeHTTP(w, r)
				return
			}
			var user *fb.User
			if provider, ok := providers[authReq.Provider]; ok {
				user, err = provider.GetUser(r.Context(), authReq.Token)
				if err != nil {
					reportError(w, err)
					return
				}
			} else {
				reportError(w, errors.Statusf(http.StatusBadRequest, "unknown auth provider `%s`", authReq.Provider))
				return
			}
			token := authdb.CreateAuthToken(user.Name, user.Salt, secret, time.Now().UTC().Unix())
			w.Header().Set("Cache-Control", "must-revalidate")
			w.Header().Add("Content-Type", "application/json")
			http.SetCookie(w, &http.Cookie{
				Name:     kivik.SessionCookieName,
				Value:    token,
				Path:     "/",
				MaxAge:   10 * 60, // 10 min, TODO: configure this
				HttpOnly: true,
			})
			if redir := r.URL.Query().Get("next"); redir != "" {
				if !strings.HasPrefix(redir, "/") {
					// Only relative redirections are permitted
					reportError(w, errors.Status(http.StatusBadRequest, "prohibited redirection"))
				}
				w.Header().Add("Location", redir)
				w.WriteHeader(kivik.StatusFound)
			} else {
				w.WriteHeader(kivik.StatusOK)
			}
			err = json.NewEncoder(w).Encode(map[string]interface{}{
				"ok":    true,
				"name":  user.Name,
				"roles": user.Roles,
			})
			if err != nil {
				reportError(w, err)
			}
		})
	}
}

type authRequest struct {
	Provider string `json:"provider"`
	Token    string `json:"access_token"`
}

func newAuthRequest(provider, token *string) (*authRequest, error) {
	if provider == nil && token == nil {
		// Do nothing, let the standard auth handler try
		return nil, nil
	}
	if provider == nil {
		return nil, errors.Status(http.StatusBadRequest, "No provider specified")
	}
	if token == nil {
		return nil, errors.Status(http.StatusBadRequest, "No access token provided")
	}
	return &authRequest{
		Provider: *provider,
		Token:    *token,
	}, nil
}

// parseAuthRequest will parse the request body for an auth request, returning
// an error if it was unable to do so. If there is no OAuth2 auth request, the
// request body is restored (by replacing the io.Reader with another that will
// return the same bytes), and nil is returned.
func parseAuthRequest(r *http.Request) (*authRequest, error) {
	var parser func([]byte) (*string, *string, error)
	switch ct, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); ct {
	case "application/json":
		parser = parseJSONAuthRequest
	case "application/x-www-form-urlencoded":
		parser = parseFormAuthRequest
	default:
		return nil, nil
	}
	if r.Body == nil || r.ContentLength == 0 {
		return nil, errors.Status(http.StatusBadRequest, "missing body")
	}
	body, err := ioutil.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		return nil, err
	}
	provider, token, err := parser(body)
	if err != nil {
		return nil, err
	}
	authReq, err := newAuthRequest(provider, token)
	if authReq == nil && err == nil {
		// Restore the body for pass-through
		r.Body = ioutil.NopCloser(bytes.NewReader(body))
	}
	return authReq, err
}

func parseFormAuthRequest(body []byte) (*string, *string, error) {
	values, err := url.ParseQuery(string(body))
	if err != nil {
		return nil, nil, errors.WrapStatus(http.StatusBadRequest, err)
	}
	var authReq struct {
		Provider *string `formam:"provider"`
		Token    *string `formam:"access_token"`
	}
	if e := formam.NewDecoder(&formam.DecoderOptions{IgnoreUnknownKeys: true}).Decode(values, &authReq); e != nil {
		return nil, nil, errors.WrapStatus(http.StatusBadRequest, e)
	}
	return authReq.Provider, authReq.Token, nil
}

func parseJSONAuthRequest(body []byte) (*string, *string, error) {
	var authReq struct {
		Provider *string `json:"provider"`
		Token    *string `json:"access_token"`
	}
	if err := json.Unmarshal(body, &authReq); err != nil {
		return nil, nil, errors.WrapStatus(http.StatusBadRequest, err)
	}
	return authReq.Provider, authReq.Token, nil
}
