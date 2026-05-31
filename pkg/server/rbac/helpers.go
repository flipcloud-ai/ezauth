package rbac

import (
	"fmt"
	"regexp"
	"strings"

	lru "github.com/hashicorp/golang-lru/v2"
)

var permissionRe = regexp.MustCompile(`^(?P<Service>[A-Za-z][A-Za-z0-9_-]{1,16})::(?P<Resource>[A-Za-z*][A-Za-z0-9_-]{0,16})::(?P<Action>[A-Za-z0-9*_-]{1,16})`)

func parsePermission(action string) (string, string, string, error) {
	matches := permissionRe.FindStringSubmatch(action)
	if len(matches) < 4 {
		return "", "", "", fmt.Errorf("invalid action format")
	}
	return matches[permissionRe.SubexpIndex("Service")],
		matches[permissionRe.SubexpIndex("Resource")],
		matches[permissionRe.SubexpIndex("Action")], nil
}

// wildcardPathFromPaths computes a wildcard path pattern from a set of route paths.
// It finds the longest common directory prefix and appends "*".
// Example: ["/admin/users/", "/admin/users/{id}"] → "/admin/users/*"
func wildcardPathFromPaths(paths []string) string {
	if len(paths) == 0 {
		return ""
	}

	// Extract directory part of each path (up to and including last '/')
	dirs := make([]string, len(paths))
	for i, p := range paths {
		if idx := strings.LastIndex(p, "/"); idx >= 0 {
			dirs[i] = p[:idx+1]
		} else {
			dirs[i] = "/"
		}
	}

	prefix := dirs[0]
	for _, d := range dirs[1:] {
		for !strings.HasPrefix(d, prefix) {
			if idx := strings.LastIndex(prefix[:len(prefix)-1], "/"); idx >= 0 {
				prefix = prefix[:idx+1]
			} else {
				prefix = "/"
				break
			}
		}
	}

	return prefix + "*"
}

const pathPatternCacheSize = 1024

var (
	templateRe       = regexp.MustCompile(`\{[^/]+\}`)
	pathPatternCache = func() *lru.Cache[string, *regexp.Regexp] {
		c, _ := lru.New[string, *regexp.Regexp](pathPatternCacheSize)
		return c
	}()
)

// matchPath expects path to already be normalized by the caller (see
// normalizePath). The pattern is normalized here since patterns are stored
// in persistence and may carry trailing slashes.
func matchPath(path, pattern string) bool {
	re, err := compilePathPattern(normalizePath(pattern))
	if err != nil {
		return false
	}
	return re.MatchString(path)
}

// normalizePath strips any trailing slash (except on "/" itself) so that
// "/admin" and "/admin/" match interchangeably.
func normalizePath(p string) string {
	if len(p) > 1 && p[len(p)-1] == '/' {
		return p[:len(p)-1]
	}
	return p
}

func compilePathPattern(pattern string) (*regexp.Regexp, error) {
	if v, ok := pathPatternCache.Get(pattern); ok {
		return v, nil
	}
	parts := templateRe.Split(pattern, -1)
	for i, p := range parts {
		parts[i] = regexp.QuoteMeta(p)
	}
	expr := strings.Join(parts, `[^/]+`)
	expr = strings.ReplaceAll(expr, `/\*`, `/.*`)

	re, err := regexp.Compile(`^` + expr + `$`)
	if err != nil {
		return nil, fmt.Errorf("compile path pattern %q: %w", pattern, err)
	}
	// Get+Add is not atomic: concurrent misses for the same novel pattern
	// each compile and store independently. This is acceptable because
	// regexp.Compile is pure and idempotent; the extra work is bounded to
	// the number of concurrent goroutines hitting one new pattern, not
	// the total request volume.
	pathPatternCache.Add(pattern, re)
	return re, nil
}

func matchMethod(method, pattern string) bool {
	if pattern == "*" || strings.EqualFold(pattern, "ALL") {
		return true
	}
	return strings.EqualFold(method, pattern)
}
