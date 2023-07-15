package main

import (
	"encoding/json"
	"log"
	"net/http"
)

type Response struct {
	Message string `json:"message"`
}

func main() {
	http.HandleFunc("/hello", func(w http.ResponseWriter, r *http.Request) {
		response := &Response{Message: "Hello, world!"}
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(response); err != nil {
			log.Fatalf("Failed to encode response: %v", err)
		}
	})

	log.Fatal(http.ListenAndServe(":8080", nil))
}
