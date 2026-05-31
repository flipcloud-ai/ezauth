package server

import (
	"net/http"
	"net/http/httputil"
	stdpath "path"
	"strings"

	ezcfg "github.com/flipcloud-ai/ezauth/config"
)

// cleanedSkipAuth is the runtime representation of SkipAuthConfig with paths
// and comparison strings pre-computed at startup to avoid per-request work.
type cleanedSkipAuth struct {
	cleanedPath string
	method      string // ToUpper, compared with == at runtime
	match       string // ToLower, compared with == "prefix" at runtime
}

// proxy encapsulates reverse-proxy runtime behaviour and is only
// initialised in proxy mode. In auth-only mode Server.revProxy is nil.
type proxy struct {
	rp        *httputil.ReverseProxy
	skipPaths []cleanedSkipAuth
}

func newProxy(rp *httputil.ReverseProxy, cfgs []ezcfg.SkipAuthConfig) *proxy {
	entries := make([]cleanedSkipAuth, 0, len(cfgs))
	for _, cfg := range cfgs {
		entries = append(entries, cleanedSkipAuth{
			cleanedPath: stdpath.Clean(cfg.Path),
			method:      strings.ToUpper(cfg.Method),
			match:       strings.ToLower(cfg.Match),
		})
	}
	return &proxy{
		rp:        rp,
		skipPaths: entries,
	}
}

func (pr *proxy) matchSkipAuth(req *http.Request) bool {
	if len(pr.skipPaths) == 0 {
		return false
	}
	reqPath := stdpath.Clean(req.URL.Path)
	reqMethod := strings.ToUpper(req.Method)
	for _, entry := range pr.skipPaths {
		if entry.method != "" && entry.method != reqMethod {
			continue
		}
		switch entry.match {
		case "prefix":
			if reqPath == entry.cleanedPath || strings.HasPrefix(reqPath, entry.cleanedPath+"/") {
				return true
			}
		default:
			if reqPath == entry.cleanedPath {
				return true
			}
		}
	}
	return false
}
