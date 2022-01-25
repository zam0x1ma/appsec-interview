package main

import (
    "crypto/rand"
    "fmt"
    "math/big"
)

func main() {
    questions := []string {
        "ssrf",
        "sql-injection",
        "cross-site-scripting",
        "content-security-policy",
        "csrf",
        "xxe",
        "request-smuggling",
        "os-command-injection",
        "server-side-template-injection",
        "deserialization",
        "file-path-traversal",
        "file-upload",
        "cors",
        "sop",
        "idor",
        "owasp-top-10",
    }

    random_num, err := rand.Int(rand.Reader, big.NewInt(int64(len(questions))))
    if err != nil {
        panic(err)
    }
    idx := random_num.Int64() 
    fmt.Println(questions[idx])
}
