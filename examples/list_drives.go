package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/tonimelisma/onedrive-sdk-go"
)

// Register with Microsoft Azure to get your own client ID
const clientID = "FILL-IN-YOUR-CLIENT-ID-HERE"

// Main
func main() {
	client, err := initializeOnedriveClient()
	if err != nil {
		log.Fatalf("Error during OneDrive client initialization: %v\n", err)
	}

	fmt.Println("Getting drives...")
	err = onedrive.GetMyDrives(client)
	if err != nil {
		log.Fatal(err)
	}
}

func authenticateOnedriveClient(ctx context.Context, oauthConfig *onedrive.OAuthConfig) (token *onedrive.OAuthToken, err error) {
	authURL, codeVerifier, err := onedrive.StartAuthentication(ctx, oauthConfig)
	if err != nil {
		return nil, err
	}

	fmt.Println("Visit the following URL in your browser and authorize the app:", authURL)
	fmt.Print("Enter the authorization code: ")

	var redirectURL string
	fmt.Scan(&redirectURL)

	parsedUrl, err := url.Parse(redirectURL)
	if err != nil {
		return nil, fmt.Errorf("parsing redirect URL: %v", err)
	}

	code := parsedUrl.Query().Get("code")
	if code == "" {
		return nil, fmt.Errorf("authorization code not found in the URL")
	}

	token, err = onedrive.CompleteAuthentication(ctx, oauthConfig, code, codeVerifier)
	if err != nil {
		return nil, err
	}

	return token, nil
}

func initializeOnedriveClient() (*http.Client, error) {
	ctx, oauthConfig := onedrive.GetOauth2Config(clientID)

	token, err := authenticateOnedriveClient(ctx, oauthConfig)
	if err != nil {
		return nil, err
	}

	// Save the token to persistent storage so you can reload it when the program runs again

	tokenRefreshCallbackFunc := func(token onedrive.OAuthToken) {
		// This function is run when the access and refresh token are refreshed
		// Save the new token to persistent storage so you can reload it when the program runs again
	}

	client := onedrive.NewClient(ctx, oauthConfig, *token, tokenRefreshCallbackFunc)
	if client == nil {
		return nil, errors.New("client is nil")
	} else {
		return client, nil
	}
}
