package https

import "github.com/gin-gonic/gin"

func RunCertificateServer(certificateFile string, keyFile string) {
	server := gin.Default()
	server.GET("/", func(context *gin.Context) {
		context.Data(200, "text/plain", []byte("Hello World"))
	})
	err := server.RunTLS(":5001", certificateFile, keyFile)
	if err != nil {
		panic(err)
	}
}
