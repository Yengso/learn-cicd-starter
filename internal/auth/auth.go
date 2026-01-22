package auth

import (
	"errors"
	"net/http"
	"strings"
	"testing"
)

var ErrNoAuthHeaderIncluded = errors.New("no authorization header included")

// GetAPIKey -
func GetAPIKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", ErrNoAuthHeaderIncluded
	}
	splitAuth := strings.Split(authHeader, " ")
	if len(splitAuth) < 2 || splitAuth[0] != "ApiKey" {
		return "", errors.New("malformed authorization header")
	}

	return splitAuth[1], nil
}

func TestGetAPIKey(t *testing.T) {
    tests := map[string]struct {
        headers http.Header
        wantKey string
        wantErr error
    }{
        "no auth header": {
            headers: http.Header{},
            wantKey: "",
            wantErr: ErrNoAuthHeaderIncluded,
        },
        "malformed header - wrong prefix": {
            headers: func() http.Header {
                h := http.Header{}
                h.Set("Authorization", "Bearer abc123")
                return h
            }(),
            wantKey: "",
            wantErr: errors.New("malformed authorization header"),
        },
        "malformed header - missing key": {
            headers: func() http.Header {
                h := http.Header{}
                h.Set("Authorization", "ApiKey")
                return h
            }(),
            wantKey: "",
            wantErr: errors.New("malformed authorization header"),
        },
        "valid header": {
            headers: func() http.Header {
                h := http.Header{}
                h.Set("Authorization", "ApiKey abc123")
                return 
            }(),
            wantKey: "abc123",
            wantErr: nil,
        },
    }

    for name, tc := range tests {
        t.Run(name, func(t *testing.T) {
            gotKey, gotErr := GetAPIKey(tc.headers)

            // Compare error messages (since some errors are constructed inline)
            var gotErrMsg, wantErrMsg string
            if gotErr != nil {
                gotErrMsg = gotErr.Error()
            }
            if tc.wantErr != nil {
                wantErrMsg = tc.wantErr.Error()
            }

            if gotErrMsg != wantErrMsg {
                t.Fatalf("expected error %q, got %q", wantErrMsg, gotErrMsg)
            }

            if gotKey != tc.wantKey {
                t.Fatalf("expected key %q, got %q", tc.wantKey, gotKey)
            }
        })
    }
}