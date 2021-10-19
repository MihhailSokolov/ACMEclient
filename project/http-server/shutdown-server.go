package http_server

import (
	"github.com/gin-gonic/gin"
	"log"
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
	err := server.Run(":5003")
	if err != nil {
		panic(err)
	}
}