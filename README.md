[![Build Status](https://travis-ci.com/philips-software/go-hsdp-signer.svg?branch=master)](https://travis-ci.com/philips-software/go-hsdp-signer)
[![Maintainability](https://api.codeclimate.com/v1/badges/d30d55adc190015a63a6/maintainability)](https://codeclimate.com/github/philips-software/go-hsdp-signer/maintainability)
[![Test Coverage](https://api.codeclimate.com/v1/badges/d30d55adc190015a63a6/test_coverage)](https://codeclimate.com/github/philips-software/go-hsdp-signer/test_coverage)

# Go HSDP Signer

This package implements the HSDP API signing algorithm.
You can sign a http.Request instance 

## Usage

```go
package main

import (
  "github.com/philips-software/go-hsdp-signer"
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
