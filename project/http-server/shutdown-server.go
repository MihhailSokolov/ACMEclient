package http_server

import (
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
)

func RunShutdownServer(shutdownChannel chan bool) {
	server := gin.Default()
	server.GET("/shutdown", func(context *gin.Context) {
		context.JSON(200, gin.H{
			"message": "shutting down...",
		})
		log.Println("Received shutdown signal, exiting...")
		shutdownChannel <- true
	})
	err := http.ListenAndServe("0.0.0.0:5003", server)
	if err != nil {
		panic(err)
	}
}
