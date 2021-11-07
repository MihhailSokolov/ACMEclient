package http_server

import (
	"log"
	"net/http"
)

func AddEndpoint(token, data string) {
	http.HandleFunc("/.well-known/acme-challenge/"+token, func(response http.ResponseWriter, _ *http.Request) {
		response.Header().Set("Content-Type", "application/octet-stream")
		_, err := response.Write([]byte(data))
		if err != nil {
			panic(err)
		}
	})
}

func RunChallengeServer() {
	err := http.ListenAndServe("0.0.0.0:5002", nil)
	if err != nil {
		panic(err)
	}
	log.Println("Started HTTP server")
}
