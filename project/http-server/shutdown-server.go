package http_server

import (
	"github.com/gin-gonic/gin"
	"log"
	"net/http"
	"os"
)

func runShutdownServer() {
	server := gin.Default()
	server.GET("/shutdown", func(context *gin.Context) {
		context.JSON(200, gin.H{
			"message": "shutting down...",
		})
		log.Println("Received shutdown signal, exiting...")
		os.Exit(0)
	})
	go func() {
		err := http.ListenAndServe(":5003", server)
		if err != nil {
			panic(err)
		}
	}()
}