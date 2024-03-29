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

// OAuth2 scopes and endpoints
var oAuthScopes = []string{"offline_access", "files.readwrite.all"}

const (
	oAuthAuthURL  = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
	oAuthTokenURL = "https://login.microsoftonline.com/common/oauth2/v2.0/token"
	rootUrl       = "https://graph.microsoft.com/v1.0/"
)

// OAuthToken represents an OAuth2 Token.
type OAuthToken oauth2.Token

// OAuthConfig represents an OAuth2 Config.
type OAuthConfig oauth2.Config

// Sentinel errors
var (
	ErrReauthRequired   = errors.New("re-authentication required")
	ErrAccessDenied     = errors.New("access denied")
	ErrRetryLater       = errors.New("retry later")
	ErrInvalidRequest   = errors.New("invalid request")
	ErrResourceNotFound = errors.New("resource not found")
	ErrConflict         = errors.New("conflict")
	ErrQuotaExceeded    = errors.New("quota exceeded")
)

// Custom token source to allow for caching refreshed tokens
// (golang oauth2 library issue #84, not fixed for 6 years and counting)

type customTokenSource struct {
	base           oauth2.TokenSource
	cachedToken    *oauth2.Token
	onTokenRefresh func(OAuthToken)
}

func (cts *customTokenSource) Token() (*oauth2.Token, error) {
	logger.Debug("Token called in customTokenSource")
	token, err := cts.base.Token()
	if err != nil {
		return nil, err
	}

	// Compare the new token with the cached token
	if cts.cachedToken == nil || token.AccessToken != cts.cachedToken.AccessToken {
		// Tokens are different, indicating a refresh
		if cts.onTokenRefresh != nil {
			cts.onTokenRefresh(OAuthToken(*token))
		}
		cts.cachedToken = token // Update the cached token
	}

	return token, nil
}

// Logger is the interface that the SDK uses for logging.

type Logger interface {
	Debug(v ...interface{})
	// Add more methods if needed
}

type DefaultLogger struct{}

// The Debug method by default is empty
func (l DefaultLogger) Debug(v ...interface{}) {}

// Instantiate the default logger
var logger Logger = DefaultLogger{}

// SetLogger allows users of the SDK to set their own logger
func SetLogger(l Logger) {
	logger = l
}

// apiCall handles the HTTP GET request and categorizes common errors.
func apiCall(client *http.Client, method, url string) (*http.Response, error) {
	logger.Debug("apiCall invoked with method: ", method, ", URL: ", url)

	if client == nil {
		return nil, errors.New("HTTP client is nil, please provide a valid HTTP client")
	}

	req, err := http.NewRequest(method, url, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request failed: %v", err)
	}

	logger.Debug("Request created, sending request...")
	res, err := client.Do(req)
	if err != nil {
		var oauth2RetrieveError *oauth2.RetrieveError
		if errors.As(err, &oauth2RetrieveError) {
			switch oauth2RetrieveError.ErrorCode {
			case "invalid_request", "invalid_client", "invalid_grant",
				"unauthorized_client", "unsupported_grant_type",
				"invalid_scope", "access_denied":
				return nil, fmt.Errorf("%w: %v", ErrReauthRequired, err)
			case "server_error", "temporarily_unavailable":
				return nil, fmt.Errorf("%w: %v", ErrRetryLater, err)
			default:
				return nil, fmt.Errorf("other oauth2 error: %v", err)
			}
		} else {
			// Likely a network error?
			return nil, fmt.Errorf("network error: %v", err)
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

		jsonErr := json.Unmarshal(resBody, &oneDriveError)

		if jsonErr == nil && oneDriveError.Error.Code != "" {
			switch oneDriveError.Error.Code {
			case "accessDenied":
				return nil, fmt.Errorf("%w: %s", ErrAccessDenied, oneDriveError.Error.Message)
			case "activityLimitReached":
				return nil, fmt.Errorf("%w: %s", ErrRetryLater, oneDriveError.Error.Message)
			case "itemNotFound":
				return nil, fmt.Errorf("%w: %s", ErrResourceNotFound, oneDriveError.Error.Message)
			case "nameAlreadyExists":
				return nil, fmt.Errorf("%w: %s", ErrConflict, oneDriveError.Error.Message)
			case "invalidRange", "invalidRequest", "malwareDetected",
				"notAllowed", "notSupported", "resourceModified",
				"resyncRequired", "generalException":
				return nil, fmt.Errorf("%w: %s", ErrInvalidRequest, oneDriveError.Error.Message)
			case "quotaLimitReached":
				return nil, fmt.Errorf("%w: %s", ErrQuotaExceeded, oneDriveError.Error.Message)
			case "unauthenticated":
				return nil, fmt.Errorf("%w: %s", ErrReauthRequired, oneDriveError.Error.Message)
			case "serviceNotAvailable":
				return nil, fmt.Errorf("%w: %s", ErrRetryLater, oneDriveError.Error.Message)
			default:
				return nil, fmt.Errorf(
					"OneDrive error: %s - %s",
					res.Status,
					oneDriveError.Error.Message,
				)
			}
		} else {
			switch res.StatusCode {
			case http.StatusBadRequest, http.StatusMethodNotAllowed, http.StatusNotAcceptable,
				http.StatusLengthRequired, http.StatusPreconditionFailed,
				http.StatusRequestEntityTooLarge, http.StatusUnsupportedMediaType,
				http.StatusRequestedRangeNotSatisfiable, http.StatusUnprocessableEntity:
				return nil, fmt.Errorf("%w: %s", ErrInvalidRequest, oneDriveError.Error.Message)
			case http.StatusUnauthorized, http.StatusForbidden:
				return nil, fmt.Errorf("%w: %s", ErrReauthRequired, oneDriveError.Error.Message)
			case http.StatusGone, http.StatusNotFound:
				return nil, fmt.Errorf("%w: %s", ErrResourceNotFound, oneDriveError.Error.Message)
			case http.StatusConflict:
				return nil, fmt.Errorf("%w: %s", ErrConflict, oneDriveError.Error.Message)
			case http.StatusInsufficientStorage:
				return nil, fmt.Errorf("%w: %s", ErrQuotaExceeded, oneDriveError.Error.Message)
			case http.StatusNotImplemented,
				http.StatusTooManyRequests,
				http.StatusInternalServerError, http.StatusServiceUnavailable, 509:
				return nil, fmt.Errorf("%w: %s", ErrRetryLater, oneDriveError.Error.Message)
			default:
				return nil, fmt.Errorf("HTTP error: %s - %s", res.Status, oneDriveError.Error.Message)
			}
		}
	}

	return res, nil
}

// GetMyDrives retrieves the drives information.
func GetMyDrives(client *http.Client) error {
	logger.Debug("GetMyDrives called")

	res, err := apiCall(client, "GET", rootUrl+"me/drive/root/children")
	if err != nil {
		return err
	}
	defer res.Body.Close()

	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		return fmt.Errorf("couldn't parse body: %v", err)
	}

	logger.Debug(
		"Response in GetMyDrives - Header: ",
		res.Header,
		", Status: ",
		res.Status,
		", Body: ",
		string(resBody),
	)

	return nil
}

// StartAuthentication initiates the OAuth authentication process.
func StartAuthentication(
	ctx context.Context,
	oauthConfig *OAuthConfig,
) (authURL string, codeVerifier string, err error) {
	logger.Debug("StartAuthentication called")
	if ctx == nil {
		return "", "", errors.New("ctx is nil")
	}
	if oauthConfig == nil {
		return "", "", errors.New("oauth configuration is nil")
	}

	verifier, err := cv.CreateCodeVerifier()
	if err != nil {
		return "", "", fmt.Errorf("creating code verifier: %v", err)
	}

	// Creating a new oauth2.Config object that we'll cast to our type conversion
	// We maintain type conversion for oauth2 so users of the SDK don't have to import it
	nativeOAuthConfig := oauth2.Config(*oauthConfig)

	authURL = nativeOAuthConfig.AuthCodeURL(
		"state",
		oauth2.SetAuthURLParam("code_challenge", verifier.CodeChallengeS256()),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
	return authURL, verifier.String(), nil
}

// CompleteAuthentication completes the OAuth authentication process.
func CompleteAuthentication(
	ctx context.Context,
	oauthConfig *OAuthConfig,
	code string,
	verifier string,
) (*OAuthToken, error) {
	if oauthConfig == nil {
		return nil, errors.New("oauth configuration is nil")
	}

	logger.Debug("Exchanging code for token in CompleteAuthentication")

	// Creating a new oauth2.Config object that we'll cast to our type conversion
	// We maintain type conversion for oauth2 so users of the SDK don't have to import it
	nativeOAuthConfig := oauth2.Config(*oauthConfig)
	token, err := nativeOAuthConfig.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		return nil, fmt.Errorf("exchanging code for token: %v", err)
	}

	oauthToken := OAuthToken(*token)
	return &oauthToken, nil
}

// NewClient creates a new HTTP client with the given OAuth token.
func NewClient(ctx context.Context, oauthConfig *OAuthConfig, token OAuthToken, tokenRefreshCallback func(OAuthToken)) *http.Client {
	if ctx == nil || oauthConfig == nil {
		return nil
	}

	// TODO Ensure the token is valid or initialized before using it

	// Creating a new oauth2.Config object that we'll cast to our type conversion
	// We maintain type conversion for oauth2 so users of the SDK don't have to import it
	nativeOAuthConfig := oauth2.Config(*oauthConfig)
	originalTokenSource := nativeOAuthConfig.TokenSource(ctx, (*oauth2.Token)(&token))
	customTokenSource := &customTokenSource{
		base:           originalTokenSource,
		onTokenRefresh: tokenRefreshCallback,
		cachedToken:    (*oauth2.Token)(&token),
	}

	return oauth2.NewClient(ctx, customTokenSource)
}

// GetOauth2Config returns the OAuth2 configuration.
func GetOauth2Config(clientID string) (context.Context, *OAuthConfig) {
	logger.Debug("Creating OAuth2 configuration in getOauth2Config")
	if clientID == "" {
		return nil, nil
	}

	// Creating a new oauth2.Config object that we'll cast to our type conversion
	// We maintain type conversion for oauth2 so users of the SDK don't have to import it
	oauth2Config := oauth2.Config{
		ClientID: clientID,
		Scopes:   oAuthScopes,
		Endpoint: oauth2.Endpoint{
			AuthURL:  oAuthAuthURL,
			TokenURL: oAuthTokenURL,
		},
	}
	return context.Background(), (*OAuthConfig)(&oauth2Config)
}
