package http_server

import (
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
)

func RunChallengeServer(token string, data string) {
	server := gin.Default()
	server.GET("/.well-known/acme-challenge/"+token, func(context *gin.Context) {
		context.Data(200, "application/octet-stream", []byte(data))
	})
	err := http.ListenAndServe("0.0.0.0:5002", server)
	if err != nil {
		panic(err)
	}
	log.Println("Started HTTP server")
}
