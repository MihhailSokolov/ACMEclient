package http_server

import (
	"github.com/gin-gonic/gin"
)

func RunChallengeServer(token string, data string) {
	server := gin.Default()
	server.GET("/.well-known/acme-challenge/"+token, func(context *gin.Context) {
		context.Data(200, "application/octet-stream", []byte(data))
	})
	err := server.Run(":5002")
	if err != nil {
		panic(err)
	}
}