[![Go Reference](https://pkg.go.dev/badge/github.com/philips-software/go-nih-signer.svg)](https://pkg.go.dev/github.com/philips-software/go-nih-signer)

# Go NIH Signer

This package implements the API signing algorithm used in various HSP APIs.
You can sign a http.Request instance 

## Usage

```go
package main

import (
  "github.com/philips-software/go-nih-signer"
  "net/http"
)

func newSigner(sharedKey, secretKey string) func(*http.Request) error {
    s, err := signer.New(sharedKey, secretKey)
    if err != nil {
       return func(req *http.Request) error {
          return err
       }
    }
    return func(req *http.Request) error {
	return s.SignRequest(req)
    }	
}

func main() {
    signRequest := newSigner("myKey", "mySecret")

    req, _ := http.NewRequest("GET", "https://example.com/some/path", nil)
    
    signRequest(req)
     
}

```
## License

Licensed is MIT
