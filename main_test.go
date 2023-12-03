package onedrive

import (
	"errors"
	"io/ioutil"
	"net/http"
	"strings"
	"testing"
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

// Repeat this pattern for each significant HTTP status code...
