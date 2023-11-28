package onedrive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	cv "github.com/nirasan/go-oauth-pkce-code-verifier"
	"golang.org/x/oauth2"
)

const rootUrl = "https://graph.microsoft.com/v1.0/"

// Sentinel errors
var (
	ErrReauthRequired = errors.New("re-authentication required")
	ErrRetryLater     = errors.New("retry later")
)

// apiCall handles the HTTP GET request and categorizes common errors.
func apiCall(client *http.Client, method, url string) (*http.Response, error) {
	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request failed: %v", err)
	}

	res, err := client.Do(req)
	if err != nil {
		var oauth2RetrieveError *oauth2.RetrieveError
		if errors.As(err, &oauth2RetrieveError) {
			switch oauth2RetrieveError.ErrorCode {
			case "invalid_request":
				return nil, fmt.Errorf("unknown oauth2 error: %v", err)
			case "invalid_client":
				return nil, fmt.Errorf("%w: %v", ErrReauthRequired, err)
			case "invalid_grant":
				return nil, fmt.Errorf("%w: %v", ErrReauthRequired, err)
			case "unauthorized_client":
				return nil, fmt.Errorf("%w: %v", ErrReauthRequired, err)
			case "unsupported_grant_type":
				return nil, fmt.Errorf("unknown oauth2 error: %v", err)
			case "invalid_scope":
				return nil, fmt.Errorf("unknown oauth2 error: %v", err)
			case "access_denied":
				return nil, fmt.Errorf("%w: %v", ErrReauthRequired, err)
			case "unsupported_response_type":
				return nil, fmt.Errorf("unknown oauth2 error: %v", err)
			case "server_error":
				return nil, fmt.Errorf("%w: %v", ErrRetryLater, err)
			case "temporarily_unavailable":
				return nil, fmt.Errorf("%w: %v", ErrRetryLater, err)
			default:
				return nil, fmt.Errorf("unknown oauth2 error: %v", err)
			}
		} else {
			// Likely a network error?
			return nil, fmt.Errorf("%w: %v", ErrRetryLater, err)
		}
	}

	if res.StatusCode >= 400 {
		defer res.Body.Close()
		resBody, _ := io.ReadAll(res.Body)

		var oneDriveError struct {
			Error struct {
				Code    string `json:"code"`
				Message string `json:"message"`
			} `json:"error"`
		}
		json.Unmarshal(resBody, &oneDriveError)

		// Handling based on HTTP status codes
		switch res.StatusCode {
		case http.StatusBadRequest, http.StatusMethodNotAllowed,
			http.StatusNotAcceptable:
			return nil, fmt.Errorf("HTTP status %s - %s: %s", res.Status,
				oneDriveError.Error.Code, oneDriveError.Error.Message)
		case http.StatusUnauthorized: // Unauthorized
			return nil, fmt.Errorf("%w: HTTP status %s - %s: %s", ErrReauthRequired, res.Status, oneDriveError.Error.Code, oneDriveError.Error.Message)
		case http.StatusForbidden: // Forbidden
			// Specific handling for Forbidden
		case http.StatusNotFound, http.StatusGone: // Not Found
			return nil, fmt.Errorf("HTTP status %s - %s: %s", res.Status, oneDriveError.Error.Code, oneDriveError.Error.Message)
		case http.StatusConflict: // Conflict
			// Specific handling for Conflict
		case http.StatusLengthRequired: // Length Required
			// Specific handling for Length Required
		case http.StatusPreconditionFailed: // Precondition Failed
			// Specific handling for Precondition Failed
		case http.StatusRequestEntityTooLarge: // Request Entity Too Large
			// Specific handling for Request Entity Too Large
		case http.StatusUnsupportedMediaType: // Unsupported Media Type
			// Specific handling for Unsupported Media Type
		case http.StatusRequestedRangeNotSatisfiable: // Requested Range Not Satisfiable
			// Specific handling for Requested Range Not Satisfiable
		case http.StatusUnprocessableEntity: // Unprocessable Entity
			// Specific handling for Unprocessable Entity
		case http.StatusTooManyRequests, http.StatusInternalServerError,
			http.StatusServiceUnavailable, 509: // Too Many Requests
			return nil, fmt.Errorf("%w: %v", ErrRetryLater, err)
		case http.StatusNotImplemented: // Not Implemented
			// Specific handling for Not Implemented
		case http.StatusInsufficientStorage: // Insufficient Storage
			// Specific handling for Insufficient Storage
		default:
			return nil, fmt.Errorf("HTTP error: %s - %s", res.Status, oneDriveError.Error.Code)
		}

		// Handling based on OneDrive-specific error codes
		switch oneDriveError.Error.Code {
		case "accessDenied":
			// Handle access denied
		case "activityLimitReached":
			// Handle activity limit reached
		case "generalException":
			// Handle general exception
		case "invalidRange":
			// Handle invalid range
		case "invalidRequest":
			// Handle invalid request
		case "itemNotFound":
			// Handle item not found
		case "malwareDetected":
			// Handle malware detected
		case "nameAlreadyExists":
			// Handle name already exists
		case "notAllowed":
			// Handle not allowed
		case "notSupported":
			// Handle not supported
		case "resourceModified":
			// Handle resource modified
		case "resyncRequired":
			// Handle resync required
		case "serviceNotAvailable":
			// Handle service not available
		case "quotaLimitReached":
			// Handle quota limit reached
		case "unauthenticated":
			// Handle unauthenticated
		default:
			return nil, fmt.Errorf("OneDrive error: %s - %s", res.Status, oneDriveError.Error.Code)
		}
	}

	return res, nil
}

// GetMyDrives retrieves the drives information.
func GetMyDrives(client *http.Client) error {
	res, err := apiCall(client, "GET", rootUrl+"me/drive/root/children")
	if err != nil {
		return err
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("couldn't parse body: %v", err)
	}

	fmt.Println("Header:\n", res.Header)
	fmt.Println("Status:\n", res.Status)
	fmt.Println("Body:\n", string(resBody))

	return nil
}

// OAuthToken represents an OAuth2 Token.
type OAuthToken oauth2.Token

// StartAuthentication initiates the OAuth authentication process.
func StartAuthentication() (authURL string, codeVerifier string, err error) {
	_, oauthConfig := getOauth2Config()
	verifier, err := cv.CreateCodeVerifier()
	if err != nil {
		return "", "", fmt.Errorf("creating code verifier: %v", err)
	}

	authURL = oauthConfig.AuthCodeURL(
		"state",
		oauth2.SetAuthURLParam("code_challenge", verifier.CodeChallengeS256()),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	return authURL, verifier.String(), nil
}

// CompleteAuthentication completes the OAuth authentication process.
func CompleteAuthentication(code string, verifier string) (*OAuthToken, error) {
	ctx, oauthConfig := getOauth2Config()

	token, err := oauthConfig.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		return nil, fmt.Errorf("exchanging code for token: %v", err)
	}

	oauthToken := OAuthToken(*token)
	return &oauthToken, nil
}

// NewClient creates a new HTTP client with the given OAuth token.
func NewClient(token OAuthToken) *http.Client {
	ctx, oauthConfig := getOauth2Config()
	return oauthConfig.Client(ctx, (*oauth2.Token)(&token))
}

// getOauth2Config returns the OAuth2 configuration.
func getOauth2Config() (context.Context, *oauth2.Config) {
	return context.Background(), &oauth2.Config{
		ClientID: "71ae7ad2-0207-4618-90d3-d21db38f9f7a",
		Scopes:   []string{"offline_access", "files.readwrite.all"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
			TokenURL: "https://login.microsoftonline.com/common/oauth2/v2.0/token",
		},
	}
}
