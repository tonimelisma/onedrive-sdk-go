package onedrive

import (
	"context"
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
func apiCall(client *http.Client, url string) (*http.Response, error) {
	res, err := client.Get(url)
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

		switch res.StatusCode {
		case http.StatusUnauthorized:
			return nil, err
		case http.StatusInternalServerError:
			return nil, err
		default:
			return nil, fmt.Errorf("HTTP error: %s: %s", res.Status, string(resBody))
		}
	}

	return res, nil
}

// GetMyDrives retrieves the drives information.
func GetMyDrives(client *http.Client) error {
	res, err := apiCall(client, rootUrl+"me/drive/root/children")
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
