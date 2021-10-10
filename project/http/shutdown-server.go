package http

import (
	"github.com/gin-gonic/gin"
	"log"
)

func runShutdownServer() {
	server := gin.Default()
	server.GET("/shutdown", func(context *gin.Context) {
		context.JSON(200, gin.H{
			"message": "shutting down...",
		})
		log.Println("Received shutdown signal")
		// TODO: Shutdown all services
	})
	err := server.Run(":5003")
	if err != nil {
		panic(err)
	}
}