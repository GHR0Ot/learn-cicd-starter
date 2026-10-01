package auth

import (
	"errors"
	"net/http"
	"testing"
)

func TestGetAPIKey(t *testing.T) {
	tests := []struct {
		name         string
		headers      http.Header
		expectedKey  string
		expectedErr  error
		expectingErr bool
	}{
		{
			name:         "Valid ApiKey header",
			headers:      http.Header{"Authorization": []string{"ApiKey secret123"}},
			expectedKey:  "secret123",
			expectedErr:  nil,
			expectingErr: false,
		},
		{
			name:         "Missing Authorization header",
			headers:      http.Header{},
			expectedKey:  "",
			expectedErr:  ErrNoAuthHeaderIncluded,
			expectingErr: true,
		},
		{
			name:         "Malformed Authorization header (wrong scheme)",
			headers:      http.Header{"Authorization": []string{"Bearer secret123"}},
			expectedKey:  "",
			expectedErr:  errors.New("malformed authorization header"),
			expectingErr: true,
		},
		{
			name:         "Malformed Authorization header (missing token)",
			headers:      http.Header{"Authorization": []string{"ApiKey"}},
			expectedKey:  "",
			expectedErr:  errors.New("malformed authorization header"),
			expectingErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, err := GetAPIKey(tt.headers)

			if tt.expectingErr {
				if err == nil {
					t.Fatalf("expected error but got none")
				}
				if tt.expectedErr != nil && err.Error() != tt.expectedErr.Error() {
					t.Errorf("expected error %v, got %v", tt.expectedErr, err)
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
				if key != tt.expectedKey {
					t.Errorf("expected key %q, got %q", tt.expectedKey, key)
				}
			}
		})
	}
}
