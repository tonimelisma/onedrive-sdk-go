package onedrive

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func Test_apiCall(t *testing.T) {
	tests := []struct {
		name    string
		server  func() *httptest.Server
		wantErr bool
		errType error
	}{
		{
			name: "HTTP request fails",
			server: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Error(w, "Bad Request", http.StatusBadRequest)
				}))
			},
			wantErr: true,
			errType: fmt.Errorf("HTTP error: 400 Bad Request: Bad Request"),
		},
		{
			name: "HTTP response contains an invalid_grant error",
			server: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
				}))
			},
			wantErr: true,
			errType: ErrGrantExpired,
		},
		{
			name: "HTTP response status code is http.StatusUnauthorized",
			server: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
				}))
			},
			wantErr: true,
			errType: ErrAuthRequired,
		},
		{
			name: "HTTP response status code is http.StatusInternalServerError",
			server: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				}))
			},
			wantErr: true,
			errType: ErrInternalError,
		},
		{
			name: "HTTP response status code is not one of the above",
			server: func() *httptest.Server {
				return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					http.Error(w, "Not Found", http.StatusNotFound)
				}))
			},
			wantErr: true,
			errType: fmt.Errorf("HTTP error: 404 Not Found: Not Found"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := tt.server()
			defer server.Close()

			client := server.Client()
			_, err := apiCall(client, server.URL)
			if (err != nil) != tt.wantErr {
				t.Errorf("apiCall() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if err != nil && err.Error() != tt.errType.Error() {
				t.Errorf("apiCall() error type = %v, wantErrType %v", err, tt.errType)
			}
		})
	}
}
