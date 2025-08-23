package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	type want struct {
		apiKey string
		err    error
	}
	tests := map[string]struct {
		input http.Header
		want  want
	}{
		"valid": {
			input: http.Header{"Authorization": []string{"ApiKey abc12345temp"}},
			want: want{
				apiKey: "abc12345",
				err:    nil,
			},
		},
		"missing authorization header": {
			input: http.Header{},
			want: want{
				apiKey: "",
				err:    ErrNoAuthHeaderIncluded,
			},
		},
		"missing api key": {
			input: http.Header{"Authorization": []string{"ApiKey"}},
			want: want{
				apiKey: "",
				err:    ErrMalformedAuthHeader,
			},
		},
		"malformed api key": {
			input: http.Header{"Authorization": []string{"ApiKeyabc12345"}},
			want: want{
				apiKey: "",
				err:    ErrMalformedAuthHeader,
			},
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := GetAPIKey(tc.input)
			if got != tc.want.apiKey {
				t.Errorf("got: %v, want: %v", got, tc.want.apiKey)
			}
			if !errors.Is(err, tc.want.err) {
				t.Errorf("got: %v, want: %v", err, tc.want.err)
			}
		})
	}
}
