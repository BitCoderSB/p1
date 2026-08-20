package repositoryidentity

import (
	"errors"
	"net/url"
	"strings"
)

// Normalize removes transport credentials and makes common HTTPS, SSH, and
// SCP-like clone URLs converge on one repository identity.
func Normalize(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", nil
	}
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Host == "" {
			return "", errors.New("repository remote URL is invalid")
		}
		parsed.User = nil
		parsed.RawQuery = ""
		parsed.Fragment = ""
		return canonical(parsed.Host, parsed.EscapedPath()), nil
	}
	// SCP-like remotes use user@host:path. The user portion can itself be an
	// access token, so it is never part of the stored identity.
	hadSCPUser := false
	if at := strings.Index(value, "@"); at > 0 && strings.Contains(value[at+1:], ":") {
		hadSCPUser = true
		value = value[at+1:]
	}
	if cut := strings.IndexAny(value, "?#"); cut >= 0 {
		value = value[:cut]
	}
	if strings.HasPrefix(value, "[") {
		if closeBracket := strings.IndexByte(value, ']'); closeBracket > 0 {
			host := value[:closeBracket+1]
			remainder := value[closeBracket+1:]
			if strings.HasPrefix(remainder, "/") {
				return canonical(host, remainder), nil
			}
			if strings.HasPrefix(remainder, ":") {
				remainder = remainder[1:]
				if slash := strings.IndexByte(remainder, '/'); !hadSCPUser && slash > 0 && allDigits(remainder[:slash]) {
					return canonical(host+":"+remainder[:slash], remainder[slash+1:]), nil
				}
				return canonical(host, remainder), nil
			}
		}
	}
	if colon := strings.IndexByte(value, ':'); colon > 0 {
		isWindowsDrive := colon == 1 && len(value) > 2 &&
			((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) &&
			(value[2] == '\\' || value[2] == '/')
		if !isWindowsDrive && !strings.ContainsAny(value[:colon], `/\`) {
			remainder := value[colon+1:]
			if slash := strings.IndexByte(remainder, '/'); !hadSCPUser && slash > 0 && allDigits(remainder[:slash]) {
				return canonical(value[:colon]+":"+remainder[:slash], remainder[slash+1:]), nil
			}
			return canonical(value[:colon], remainder), nil
		}
	}
	return value, nil
}

func allDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

func canonical(host, path string) string {
	host = strings.ToLower(strings.TrimSpace(host))
	path = strings.Trim(strings.TrimSpace(path), "/")
	path = strings.TrimSuffix(path, ".git")
	if path == "" {
		return host
	}
	return host + "/" + path
}
