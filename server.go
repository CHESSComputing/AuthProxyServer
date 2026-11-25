package main

import (
	"embed"
	"log"

	srvConfig "github.com/CHESSComputing/golib/config"
	server "github.com/CHESSComputing/golib/server"
	"github.com/CHESSComputing/golib/services"
	"github.com/gin-gonic/gin"
)

//go:embed static
var StaticFs embed.FS

// Verbose defines verbosity level
var Verbose int
var _httpReadRequest *services.HttpRequest

// helper function to define our header
func header() string {
	return server.Header(StaticFs, srvConfig.Config.AuthProxyServer.WebServer.Base)
}

// helper function to define our footer
func footer() string {
	return server.Footer(StaticFs, srvConfig.Config.AuthProxyServer.WebServer.Base)
}

// helper function to setup our router
func setupRouter() *gin.Engine {
	routes := []server.Route{
		{Method: "GET", Path: "/", Handler: MainHandler},
		{Method: "GET", Path: "/login", Handler: LoginHandler},
		{Method: "GET", Path: "/logout", Handler: LogoutHandler},
		{Method: "GET", Path: "/id4b/*path", Handler: ProxyHandler},
		{Method: "GET", Path: "/id3a/*path", Handler: ProxyHandler},
		{Method: "GET", Path: "/id3b/*path", Handler: ProxyHandler},
		{Method: "GET", Path: "/id7a/*path", Handler: ProxyHandler},
		{Method: "GET", Path: "/id1a3/*path", Handler: ProxyHandler},
		{Method: "GET", Path: "/github/login", Handler: GithubOauthLoginHandler},
		{Method: "GET", Path: "/github/callback", Handler: GithubCallBackHandler},
		{Method: "GET", Path: "/google/login", Handler: GoogleOauthLoginHandler},
		{Method: "GET", Path: "/google/callback", Handler: GoogleCallBackHandler},
		{Method: "GET", Path: "/facebook/login", Handler: FacebookOauthLoginHandler},
		{Method: "GET", Path: "/facebook/callback", Handler: FacebookCallBackHandler},
		{Method: "POST", Path: "/login", Handler: KAuthHandler},
	}
	r := server.Router(routes, nil, "static", srvConfig.Config.AuthProxyServer.WebServer)
	return r
}

// Server defines our HTTP server
func Server() {
	// init Verbose
	Verbose = srvConfig.Config.AuthProxyServer.WebServer.Verbose
	// initialize http request
	_httpReadRequest = services.NewHttpRequest("read", Verbose)
	log.Printf("Starting APS with backends: %+v", srvConfig.Config.AuthProxyServer.Backends)

	// setup web router and start the service
	r := setupRouter()
	webServer := srvConfig.Config.AuthProxyServer.WebServer
	server.StartServer(r, webServer)
}
