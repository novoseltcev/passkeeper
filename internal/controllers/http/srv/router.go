package srv

import (
	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"
)

func AddRoutes(rg *gin.RouterGroup) {
	rg.GET("/ping", Ping)
	pprof.RouteRegister(rg, "/pprof")
}
