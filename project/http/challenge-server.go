package http

import (
	"github.com/gin-gonic/gin"
	"log"
)

func runChallengeServer() {
	server := gin.Default()
	server.GET("/", func(context *gin.Context) {
		context.JSON(200, gin.H{
			"message": "challenge",
		})
		log.Println("Received challenge")
		// TODO: Handle challenge
	})
	err := server.Run(":5002")
	if err != nil {
		panic(err)
	}
}