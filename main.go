package onedrive

import (
	"fmt"
	"io"
	"log"
	"net/http"
)

const rootUrl = "https://graph.microsoft.com/v1.0/"
const resourceUrl = "me/"

func GetMyDrives(client *http.Client) {
	res, err := client.Get(rootUrl + resourceUrl + "drives")
	if err != nil {
		log.Fatalf("couldn't get HTTP: %v", err)
	}
	fmt.Println("Header:\n", res.Header)
	fmt.Println("Status:\n", res.StatusCode)
	resBody, err := io.ReadAll(res.Body)
	if err != nil {
		log.Fatalf("couldn't parse body: %v", err)
	}
	fmt.Println("Body:\n", string(resBody))
}
