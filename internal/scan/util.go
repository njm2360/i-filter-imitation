package scan

import "net/http"

// filenameFrom extracts a filename from Content-Disposition or the URL path.
func filenameFrom(req *http.Request, resp *http.Response) string {
	if cd := resp.Header.Get("Content-Disposition"); cd != "" {
		for _, part := range splitParts(cd) {
			part = trimASCIISpace(part)
			const pfx = "filename="
			if len(part) > len(pfx) && foldEqual(part[:len(pfx)], pfx) {
				name := part[len(pfx):]
				if len(name) >= 2 && name[0] == '"' && name[len(name)-1] == '"' {
					return name[1 : len(name)-1]
				}
				return name
			}
		}
	}
	path := req.URL.Path
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '/' {
			if name := path[i+1:]; name != "" {
				return name
			}
			break
		}
	}
	return "download"
}

func splitParts(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == ';' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func trimASCIISpace(s string) string {
	i, j := 0, len(s)
	for i < j && (s[i] == ' ' || s[i] == '\t') {
		i++
	}
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t') {
		j--
	}
	return s[i:j]
}

func foldEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		ca, cb := a[i]|0x20, b[i]|0x20
		if ca != cb {
			return false
		}
	}
	return true
}
