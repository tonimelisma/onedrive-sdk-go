package onedrive

import (
	"context"
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"

	"golang.org/x/oauth2"
)

// Mocking the HTTP client and RoundTripper
type mockTransportFunc func(req *http.Request) *http.Response

func (f mockTransportFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

func mockHttpClient(code int, body string) *http.Client {
	return &http.Client{
		Transport: mockTransportFunc(func(req *http.Request) *http.Response {
			return &http.Response{
				StatusCode: code,
				Body:       ioutil.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}
		}),
	}
}

// Test for OAuth2 Error: Invalid Request
func TestApiCall_OAuth2InvalidRequest(t *testing.T) {
	client := mockHttpClient(http.StatusUnauthorized, `{"error": "invalid_request"}`)
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrReauthRequired) {
		t.Errorf("Expected ErrReauthRequired for OAuth2 invalid_request, got %v", err)
	}
}

// OAuth2 Error Tests
func TestApiCall_OAuth2InvalidClient(t *testing.T) {
	client := mockHttpClient(http.StatusUnauthorized, `{"error": "invalid_client"}`)
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrReauthRequired) {
		t.Errorf("Expected ErrReauthRequired for OAuth2 invalid_client, got %v", err)
	}
}

func TestApiCall_OAuth2InvalidGrant(t *testing.T) {
	client := mockHttpClient(http.StatusUnauthorized, `{"error": "invalid_grant"}`)
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrReauthRequired) {
		t.Errorf("Expected ErrReauthRequired for OAuth2 invalid_grant, got %v", err)
	}
}

func TestApiCall_OAuth2UnauthorizedClient(t *testing.T) {
	client := mockHttpClient(http.StatusUnauthorized, `{"error": "unauthorized_client"}`)
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrReauthRequired) {
		t.Errorf("Expected ErrReauthRequired for OAuth2 unauthorized_client, got %v", err)
	}
}

func TestApiCall_OAuth2UnsupportedGrantType(t *testing.T) {
	client := mockHttpClient(http.StatusUnauthorized, `{"error": "unsupported_grant_type"}`)
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrReauthRequired) {
		t.Errorf("Expected ErrReauthRequired for OAuth2 unsupported_grant_type, got %v", err)
	}
}

func TestApiCall_OAuth2InvalidScope(t *testing.T) {
	client := mockHttpClient(http.StatusUnauthorized, `{"error": "invalid_scope"}`)
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrReauthRequired) {
		t.Errorf("Expected ErrReauthRequired for OAuth2 invalid_scope, got %v", err)
	}
}

func TestApiCall_OAuth2AccessDenied(t *testing.T) {
	client := mockHttpClient(http.StatusUnauthorized, `{"error": "access_denied"}`)
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrReauthRequired) {
		t.Errorf("Expected ErrReauthRequired for OAuth2 access_denied, got %v", err)
	}
}

func TestApiCall_OAuth2UnsupportedResponseType(t *testing.T) {
	client := mockHttpClient(http.StatusUnauthorized, `{"error": "unsupported_response_type"}`)
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrReauthRequired) {
		t.Errorf("Expected ErrReauthRequired for OAuth2 unsupported_response_type, got %v", err)
	}
}

func TestApiCall_OAuth2ServerError(t *testing.T) {
	client := mockHttpClient(http.StatusInternalServerError, `{"error": "server_error"}`)
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrRetryLater) {
		t.Errorf("Expected ErrRetryLater for OAuth2 server_error, got %v", err)
	}
}

func TestApiCall_OAuth2TemporarilyUnavailable(t *testing.T) {
	client := mockHttpClient(http.StatusServiceUnavailable, `{"error": "temporarily_unavailable"}`)
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrRetryLater) {
		t.Errorf("Expected ErrRetryLater for OAuth2 temporarily_unavailable, got %v", err)
	}
}

// Test for OneDrive Error: Access Denied
func TestApiCall_OneDriveAccessDenied(t *testing.T) {
	client := mockHttpClient(
		http.StatusForbidden,
		`{"error": {"code": "accessDenied", "message": "Access denied"}}`,
	)
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrAccessDenied) {
		t.Errorf("Expected ErrAccessDenied for accessDenied, got %v", err)
	}
}

// Test for OneDrive Error: Invalid Request
func TestApiCall_OneDriveInvalidRequest(t *testing.T) {
	client := mockHttpClient(
		http.StatusBadRequest,
		`{"error": {"code": "invalidRequest", "message": "Invalid request"}}`,
	)
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("Expected ErrInvalidRequest for invalidRequest, got %v", err)
	}
}

// Test for OneDrive Error: Item Not Found
func TestApiCall_OneDriveItemNotFound(t *testing.T) {
	client := mockHttpClient(
		http.StatusNotFound,
		`{"error": {"code": "itemNotFound", "message": "Item not found"}}`,
	)
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrResourceNotFound) {
		t.Errorf("Expected ErrResourceNotFound for itemNotFound, got %v", err)
	}
}

// Test for OneDrive Error: Malware Detected
func TestApiCall_OneDriveMalwareDetected(t *testing.T) {
	client := mockHttpClient(
		http.StatusForbidden,
		`{"error": {"code": "malwareDetected", "message": "Malware detected"}}`,
	)
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("Expected ErrInvalidRequest for malwareDetected, got %v", err)
	}
}

// Test for OneDrive Error: Name Already Exists
func TestApiCall_OneDriveNameAlreadyExists(t *testing.T) {
	client := mockHttpClient(
		http.StatusConflict,
		`{"error": {"code": "nameAlreadyExists", "message": "Name already exists"}}`,
	)
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrConflict) {
		t.Errorf("Expected ErrConflict for nameAlreadyExists, got %v", err)
	}
}

// Test for OneDrive Error: Not Allowed
func TestApiCall_OneDriveNotAllowed(t *testing.T) {
	client := mockHttpClient(
		http.StatusForbidden,
		`{"error": {"code": "notAllowed", "message": "Not allowed"}}`,
	)
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("Expected ErrInvalidRequest for notAllowed, got %v", err)
	}
}

// Test for OneDrive Error: Not Supported
func TestApiCall_OneDriveNotSupported(t *testing.T) {
	client := mockHttpClient(
		http.StatusBadRequest,
		`{"error": {"code": "notSupported", "message": "Not supported"}}`,
	)
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("Expected ErrInvalidRequest for notSupported, got %v", err)
	}
}

// Test for OneDrive Error: Resource Modified
func TestApiCall_OneDriveResourceModified(t *testing.T) {
	client := mockHttpClient(
		http.StatusPreconditionFailed,
		`{"error": {"code": "resourceModified", "message": "Resource modified"}}`,
	)
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("Expected ErrInvalidRequest for resourceModified, got %v", err)
	}
}

// Test for OneDrive Error: Resync Required
func TestApiCall_OneDriveResyncRequired(t *testing.T) {
	client := mockHttpClient(
		http.StatusConflict,
		`{"error": {"code": "resyncRequired", "message": "Resync required"}}`,
	)
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("Expected ErrInvalidRequest for resyncRequired, got %v", err)
	}
}

// Test for OneDrive Error: Quota Limit Reached
func TestApiCall_OneDriveQuotaLimitReached(t *testing.T) {
	client := mockHttpClient(
		http.StatusInsufficientStorage,
		`{"error": {"code": "quotaLimitReached", "message": "Quota limit reached"}}`,
	)
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("Expected ErrQuotaExceeded for quotaLimitReached, got %v", err)
	}
}

// Test for OneDrive Error: Service Not Available
func TestApiCall_OneDriveServiceNotAvailable(t *testing.T) {
	client := mockHttpClient(
		http.StatusServiceUnavailable,
		`{"error": {"code": "serviceNotAvailable", "message": "Service not available"}}`,
	)
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrRetryLater) {
		t.Errorf("Expected ErrRetryLater for serviceNotAvailable, got %v", err)
	}
}

// Test for OneDrive Error: Unauthenticated
func TestApiCall_OneDriveUnauthenticated(t *testing.T) {
	client := mockHttpClient(
		http.StatusUnauthorized,
		`{"error": {"code": "unauthenticated", "message": "Unauthenticated"}}`,
	)
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrReauthRequired) {
		t.Errorf("Expected ErrReauthRequired for unauthenticated, got %v", err)
	}
}

// Test for OneDrive Error: General Exception
func TestApiCall_OneDriveGeneralException(t *testing.T) {
	client := mockHttpClient(
		http.StatusInternalServerError,
		`{"error": {"code": "generalException", "message": "General exception occurred"}}`,
	)
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("Expected ErrRetryLater for generalException, got %v", err)
	}
}

// Test for OneDrive Error: Invalid Range
func TestApiCall_OneDriveInvalidRange(t *testing.T) {
	client := mockHttpClient(
		http.StatusRequestedRangeNotSatisfiable,
		`{"error": {"code": "invalidRange", "message": "Invalid range"}}`,
	)
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("Expected ErrInvalidRequest for invalidRange, got %v", err)
	}
}

// Test for HTTP Status Code: Bad Request
func TestApiCall_BadRequest(t *testing.T) {
	client := mockHttpClient(http.StatusBadRequest, "")
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("Expected ErrInvalidRequest for BadRequest, got %v", err)
	}
}

// Test for HTTP Status Code: Method Not Allowed
func TestApiCall_MethodNotAllowed(t *testing.T) {
	client := mockHttpClient(http.StatusMethodNotAllowed, "")
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("Expected ErrInvalidRequest for MethodNotAllowed, got %v", err)
	}
}

// Test for HTTP Status Code: Not Acceptable
func TestApiCall_NotAcceptable(t *testing.T) {
	client := mockHttpClient(http.StatusNotAcceptable, "")
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("Expected ErrInvalidRequest for NotAcceptable, got %v", err)
	}
}

// Test for HTTP Status Code: Length Required
func TestApiCall_LengthRequired(t *testing.T) {
	client := mockHttpClient(http.StatusLengthRequired, "")
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("Expected ErrInvalidRequest for LengthRequired, got %v", err)
	}
}

// Test for HTTP Status Code: Precondition Failed
func TestApiCall_PreconditionFailed(t *testing.T) {
	client := mockHttpClient(http.StatusPreconditionFailed, "")
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("Expected ErrInvalidRequest for PreconditionFailed, got %v", err)
	}
}

// Test for HTTP Status Code: Request Entity Too Large
func TestApiCall_RequestEntityTooLarge(t *testing.T) {
	client := mockHttpClient(http.StatusRequestEntityTooLarge, "")
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("Expected ErrInvalidRequest for RequestEntityTooLarge, got %v", err)
	}
}

// Test for HTTP Status Code: Unsupported Media Type
func TestApiCall_UnsupportedMediaType(t *testing.T) {
	client := mockHttpClient(http.StatusUnsupportedMediaType, "")
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("Expected ErrInvalidRequest for UnsupportedMediaType, got %v", err)
	}
}

// Test for HTTP Status Code: Requested Range Not Satisfiable
func TestApiCall_RequestedRangeNotSatisfiable(t *testing.T) {
	client := mockHttpClient(http.StatusRequestedRangeNotSatisfiable, "")
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("Expected ErrInvalidRequest for RequestedRangeNotSatisfiable, got %v", err)
	}
}

// Test for HTTP Status Code: Unprocessable Entity
func TestApiCall_UnprocessableEntity(t *testing.T) {
	client := mockHttpClient(http.StatusUnprocessableEntity, "")
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrInvalidRequest) {
		t.Errorf("Expected ErrInvalidRequest for UnprocessableEntity, got %v", err)
	}
}

// Test for HTTP Status Code: Unauthorized
func TestApiCall_Unauthorized(t *testing.T) {
	client := mockHttpClient(http.StatusUnauthorized, "")
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrReauthRequired) {
		t.Errorf("Expected ErrReauthRequired for Unauthorized, got %v", err)
	}
}

// Test for HTTP Status Code: Forbidden
func TestApiCall_Forbidden(t *testing.T) {
	client := mockHttpClient(http.StatusForbidden, "")
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrReauthRequired) {
		t.Errorf("Expected ErrReauthRequired for Forbidden, got %v", err)
	}
}

// Test for HTTP Status Code: Not Found
func TestApiCall_NotFound(t *testing.T) {
	client := mockHttpClient(http.StatusNotFound, "")
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrResourceNotFound) {
		t.Errorf("Expected ErrResourceNotFound for NotFound, got %v", err)
	}
}

// Test for HTTP Status Code: Conflict
func TestApiCall_Conflict(t *testing.T) {
	client := mockHttpClient(http.StatusConflict, "")
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrConflict) {
		t.Errorf("Expected ErrConflict for Conflict, got %v", err)
	}
}

// Test for HTTP Status Code: Insufficient Storage
func TestApiCall_InsufficientStorage(t *testing.T) {
	client := mockHttpClient(http.StatusInsufficientStorage, "")
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrQuotaExceeded) {
		t.Errorf("Expected ErrQuotaExceeded for InsufficientStorage, got %v", err)
	}
}

// Test for HTTP Status Code: Gone
func TestApiCall_Gone(t *testing.T) {
	client := mockHttpClient(http.StatusGone, "")
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrResourceNotFound) {
		t.Errorf("Expected ErrResourceNotFound for Gone, got %v", err)
	}
}

// Test for HTTP Status Code: Not Implemented
func TestApiCall_NotImplemented(t *testing.T) {
	client := mockHttpClient(http.StatusNotImplemented, "")
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrRetryLater) {
		t.Errorf("Expected ErrRetryLater for NotImplemented, got %v", err)
	}
}

// Test for HTTP Status Code: Too Many Requests
func TestApiCall_TooManyRequests(t *testing.T) {
	client := mockHttpClient(http.StatusTooManyRequests, "")
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrRetryLater) {
		t.Errorf("Expected ErrRetryLater for TooManyRequests, got %v", err)
	}
}

// Test for HTTP Status Code: Internal Server Error
func TestApiCall_InternalServerError(t *testing.T) {
	client := mockHttpClient(http.StatusInternalServerError, "")
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrRetryLater) {
		t.Errorf("Expected ErrRetryLater for InternalServerError, got %v", err)
	}
}

// Test for HTTP Status Code: Service Unavailable
func TestApiCall_ServiceUnavailable(t *testing.T) {
	client := mockHttpClient(http.StatusServiceUnavailable, "")
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrRetryLater) {
		t.Errorf("Expected ErrRetryLater for ServiceUnavailable, got %v", err)
	}
}

// Test for Custom HTTP Status Code: 509
func TestApiCall_StatusBandwidthLimitExceeded(t *testing.T) {
	client := mockHttpClient(509, "")
	_, err := apiCall(client, "GET", "https://example.com")
	if !errors.Is(err, ErrRetryLater) {
		t.Errorf("Expected ErrRetryLater for 509 Bandwidth Limit Exceeded, got %v", err)
	}
}

func TestSetLogger(t *testing.T) {
	var customLogger Logger = DefaultLogger{}
	SetLogger(customLogger)

	if logger != customLogger {
		t.Errorf("Expected logger to be set to custom logger, but it was not")
	}
}

func TestGetOauth2Config(t *testing.T) {
	clientID := "test-client-id"
	ctx, config := GetOauth2Config(clientID)

	if ctx == nil {
		t.Errorf("Expected non-nil context")
	}
	if config == nil {
		t.Fatalf("Expected non-nil config")
	}
	if config.ClientID != clientID {
		t.Errorf("Expected ClientID to be '%s', got '%s'", clientID, config.ClientID)
	}
	// Further assertions can be added for Scopes, Endpoint.AuthURL, and Endpoint.TokenURL
}

func TestStartAuthentication(t *testing.T) {
	ctx := context.Background()
	oauthConfig := &oauth2.Config{
		ClientID: "test-client-id",
		Endpoint: oauth2.Endpoint{
			AuthURL:  oAuthAuthURL,
			TokenURL: oAuthTokenURL,
		},
	}

	authURL, codeVerifier, err := StartAuthentication(ctx, (*OAuthConfig)(oauthConfig))
	if err != nil {
		t.Errorf("StartAuthentication returned an error: %v", err)
	}
	if authURL == "" || codeVerifier == "" {
		t.Errorf("StartAuthentication returned empty authURL or codeVerifier")
	}
	// Additional checks can be added to verify the format of the authURL and the codeVerifier
}

func TestCompleteAuthentication(t *testing.T) {
	ctx := context.Background()
	oauthConfig := &oauth2.Config{} // Simplified for example
	code := "test-code"
	verifier := "test-verifier"

	_, err := CompleteAuthentication(ctx, (*OAuthConfig)(oauthConfig), code, verifier)
	if err == nil {
		t.Errorf("Expected error due to invalid oauthConfig, code, or verifier, but got none")
	}
	// Further testing would require mocking the oauthConfig.Exchange call
}

func TestNewClient(t *testing.T) {
	ctx := context.Background()
	oauthConfig := &oauth2.Config{} // Simplified for example
	token := OAuthToken{}

	client := NewClient(ctx, (*OAuthConfig)(oauthConfig), token, nil)
	if client == nil {
		t.Errorf("Expected non-nil *http.Client, got nil")
	}
}
