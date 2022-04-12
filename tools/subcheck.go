package main

import (
    "fmt"
    "log"
    "net/http"
    "os"
    "crypto/tls"
)

func main() {

    url := os.Args[1]
    http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //For cancelling certificate checking
    resp, err := http.Get(url)
    if err != nil {
        log.Fatal(err)
    }

    // Print the HTTP Status Code and Status Name
    if resp.StatusCode == 404 {
        fmt.Println(url)
    } 
}