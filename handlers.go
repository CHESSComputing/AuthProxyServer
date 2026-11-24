package main

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"time"

	authz "github.com/CHESSComputing/golib/authz"
	srvConfig "github.com/CHESSComputing/golib/config"
	server "github.com/CHESSComputing/golib/server"
	"github.com/CHESSComputing/golib/utils"
	"github.com/gin-gonic/gin"
	"gopkg.in/jcmturner/gokrb5.v7/credentials"
)

const sessionTTL = 24 * time.Hour

var validUserRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

var DEFAULT_END_POINT string

//
// OAuth handlers
//

// GithubOauthLoginHandler provides kerberos authentication handler
func GithubOauthLoginHandler(c *gin.Context) {
	authz.GithubOauthLogin(c, Verbose)
}

// GithubCallBackHandler provides kerberos authentication handler
func GithubCallBackHandler(c *gin.Context) {
	authz.GithubCallBack(c, DEFAULT_END_POINT, Verbose)
}

// GoogleOauthLoginHandler provides kerberos authentication handler
func GoogleOauthLoginHandler(c *gin.Context) {
	authz.GoogleOauthLogin(c, Verbose)
}

// GoogleCallBackHandler provides kerberos authentication handler
func GoogleCallBackHandler(c *gin.Context) {
	authz.GoogleCallBack(c, DEFAULT_END_POINT, Verbose)
}

// FacebookOauthLoginHandler provides kerberos authentication handler
func FacebookOauthLoginHandler(c *gin.Context) {
	authz.FacebookOauthLogin(c, Verbose)
}

// FacebookCallBackHandler provides kerberos authentication handler
func FacebookCallBackHandler(c *gin.Context) {
	authz.FacebookCallBack(c, DEFAULT_END_POINT, Verbose)
}

func tokenCookieName(user string) string { return "auth_token_" + user }

func setCookie(c *gin.Context, name, value string, ttl time.Duration) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name: name, Value: value, Path: "/",
		Expires: time.Now().Add(ttl), MaxAge: int(ttl.Seconds()),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

func clearCookie(c *gin.Context, name string) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name: name, Value: "", Path: "/", MaxAge: -1,
		Expires: time.Unix(0, 0),
		Secure:  true, HttpOnly: true, SameSite: http.SameSiteLaxMode,
	})
}

// issueUserToken returns a signed token whose claims carry the user name.
// ADAPT: replace the body with your golib/authz call that mints a user token.
func issueUserToken(user string, ttl time.Duration) (string, error) {
	_httpReadRequest.GetUserToken(user)
	token := _httpReadRequest.Token
	return token, nil
}

// authenticate returns the verified user and the token to forward to backends.
func authenticate(c *gin.Context) (user, token string, err error) {
	if srvConfig.Config.AuthProxyServer.TestMode {
		return "test", "", nil
	}
	clientID := srvConfig.Config.Authz.ClientID

	// browser session: user cookie + auth_token_<user> cookie, which must agree
	user, err = c.Cookie("user")
	if err != nil || !validUserRe.MatchString(user) {
		return "", "", errors.New("missing or invalid user cookie")
	}
	token, err = c.Cookie(tokenCookieName(user))
	if err != nil || token == "" {
		return "", "", errors.New("missing auth token")
	}
	claims, err := authz.TokenClaims(token, clientID)
	if err != nil {
		return "", "", fmt.Errorf("invalid token: %w", err)
	}
	if claims.CustomClaims.User != user {
		return "", "", errors.New("token does not belong to user")
	}
	return user, token, nil
}

// getUser returns the authenticated user name
func getUser(c *gin.Context) (string, error) {
	user, _, err := authenticate(c)
	if err != nil {
		if Verbose > 1 {
			log.Printf("[AuthProxyServer.getUser] %v", err) // never log tokens
		}
		return "", err
	}
	return user, nil
}

// safeRedirect only allows local paths, never the Referer's foreign host
func safeRedirect(c *gin.Context) string {
	def := DEFAULT_END_POINT
	if def == "" {
		def = "/"
	}
	ref := c.GetHeader("Referer")
	if ref == "" {
		return def
	}
	u, err := url.Parse(ref)
	if err != nil || (u.Host != "" && u.Host != c.Request.Host) {
		return def
	}
	p := u.EscapedPath()
	if p == "" || p[0] != '/' || (len(p) > 1 && p[1] == '/') || p == "/login" {
		return def
	}
	if u.RawQuery != "" {
		p += "?" + u.RawQuery
	}
	return p
}

// MainHandler provides access to GET / end-point
func MainHandler(c *gin.Context) {
	user, token, err := authenticate(c)
	if err != nil || user == "" || token == "" {
		LoginHandler(c)
		return
	}
	tmpl := server.MakeTmpl(StaticFs, "main")
	base := srvConfig.Config.AuthProxyServer.WebServer.Base
	tmpl["Base"] = base
	tmplPage := srvConfig.Config.AuthProxyServer.MainPageTemplate
	content := server.TmplPage(StaticFs, tmplPage, tmpl)
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(header()+content+footer()))
}

// LoginHandler provides access to GET /login endpoint
func LoginHandler(c *gin.Context) {
	tmpl := server.MakeTmpl(StaticFs, "Login")
	base := srvConfig.Config.AuthProxyServer.WebServer.Base
	tmpl["Base"] = base
	// add oauth login buttons
	tmpl["GithubLogin"] = ""
	tmpl["GoogleLogin"] = ""
	tmpl["FacebookLogin"] = ""
	for _, arec := range srvConfig.Config.AuthProxyServer.OAuth {
		if arec.Provider == "github" {
			tmpl["GithubLogin"] = fmt.Sprintf("%s/github/login", base)
		} else if arec.Provider == "google" {
			tmpl["GoogleLogin"] = fmt.Sprintf("%s/google/login", base)
		} else if arec.Provider == "facebook" {
			tmpl["FacebookLogin"] = fmt.Sprintf("%s/facebook/login", base)
		}
	}
	content := server.TmplPage(StaticFs, "login.tmpl", tmpl)
	c.Data(http.StatusOK, "text/html; charset=utf-8", []byte(header()+content+footer()))
}

// LogoutHandler provides access to GET /logout endpoint
func LogoutHandler(c *gin.Context) {
	if user, err := c.Cookie("user"); err == nil && validUserRe.MatchString(user) {
		clearCookie(c, tokenCookieName(user))
	}
	clearCookie(c, "user")
	c.Redirect(http.StatusFound, "/")
}

func renderError(c *gin.Context, status int, msg string) {
	tmpl := server.MakeTmpl(StaticFs, "Login")
	tmpl["Base"] = srvConfig.Config.AuthProxyServer.WebServer.Base
	tmpl["Content"] = msg
	content := server.TmplPage(StaticFs, "error.tmpl", tmpl)
	c.Data(status, "text/html; charset=utf-8", []byte(header()+content+footer()))
}

// ProxyHandler authenticates the user and forwards the request to the
// configured backend with an "Authorization: Bearer <token>" header.
func ProxyHandler(c *gin.Context) {
	_, token, err := authenticate(c)
	if err != nil {
		LoginHandler(c)
		return
	}
	// perform authorization based on user's scopes/btrs
	clientID := srvConfig.Config.Authz.ClientID
	claims, err := authz.TokenClaims(token, clientID)
	if err != nil {
		log.Printf("bad claims %v: %v", claims, err)
		renderError(c, http.StatusInternalServerError, "authorization error")
		return
	}
	if claims.CustomClaims.Scope != "read" {
		log.Printf("wrong scope %s: expect read", claims.CustomClaims.Scope)
		renderError(c, http.StatusInternalServerError, "authorization error")
		return
	}
	userBtrs := claims.CustomClaims.Btrs

	// check if available backend endpoint exists and if so redirect to it
	for _, backend := range srvConfig.Config.AuthProxyServer.Backends {
		if backend.Endpoint != c.Request.URL.Path {
			continue
		}
		matchedBtr := false
		for _, btr := range backend.Btrs {
			if utils.InList(btr, userBtrs) {
				matchedBtr = true
			}
		}
		if !matchedBtr {
			continue
		}
		target, err := url.Parse(backend.Url)
		if err != nil {
			log.Printf("bad backend url %q: %v", backend.Url, err)
			renderError(c, http.StatusInternalServerError, "backend misconfigured")
			return
		}
		proxy := &httputil.ReverseProxy{
			Rewrite: func(pr *httputil.ProxyRequest) {
				// route outbound request to the backend scheme/host/query,
				// SetURL also rewrites the outbound Host header to target.Host
				pr.SetURL(target)

				// go to the backend URL exactly as configured, not target + incoming path
				pr.Out.URL.Path = target.Path
				pr.Out.URL.RawPath = ""

				// do not leak browser session cookies to the backend
				pr.Out.Header.Del("Cookie")

				// Set replaces any client-supplied Authorization header
				pr.Out.Header.Set("Authorization", "Bearer "+token)

				// optional: add X-Forwarded-For/Host/Proto
				pr.SetXForwarded()
			},
			ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
				log.Printf("backend request failed: %v", err)
				http.Error(w, "backend unavailable", http.StatusBadGateway)
			},
		}
		proxy.ServeHTTP(c.Writer, c.Request)

		return
	}
	renderError(c, http.StatusNotFound, "no backend configured for this endpoint")
}

// KAuthHandler provides kerberos authentication handler
func KAuthHandler(c *gin.Context) {
	redirectTo := safeRedirect(c)

	// already authenticated with a verified session
	if user, err := getUser(c); err == nil && user != "" {
		c.Redirect(http.StatusFound, redirectTo)
		return
	}

	if err := c.Request.ParseForm(); err != nil {
		renderError(c, http.StatusBadRequest, "could not parse http form")
		return
	}
	name := c.Request.PostFormValue("name") // POST body only, not URL query
	password := c.Request.PostFormValue("password")
	if name == "" || password == "" || !validUserRe.MatchString(name) {
		renderError(c, http.StatusBadRequest, "invalid user name or empty password")
		return
	}
	var creds *credentials.Credentials
	creds, err := kuser(name, password)
	if err != nil || creds == nil {
		log.Printf("kerberos login failed for %q: %v", name, err)
		renderError(c, http.StatusUnauthorized, "wrong user credentials")
		return
	}

	token, err := issueUserToken(name, sessionTTL)
	if err != nil {
		log.Printf("token issue failed for %q: %v", name, err)
		renderError(c, http.StatusInternalServerError, "unable to issue token")
		return
	}
	setCookie(c, "user", name, sessionTTL)
	setCookie(c, tokenCookieName(name), token, sessionTTL)
	c.Redirect(http.StatusFound, redirectTo)
}
