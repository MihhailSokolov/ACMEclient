package https

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func RunCertificateServer(certificateFile string, keyFile string) {
	server := gin.Default()
	server.GET("/", func(context *gin.Context) {
		context.Data(200, "text/plain", []byte("Hello World"))
	})
	err := http.ListenAndServeTLS(":5001", certificateFile, keyFile, server)
	if err != nil {
		panic(err)
	}
}
