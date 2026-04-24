package proxy

import (
	"net"
	"strings"
)

// trieNode is a node in the reversed-label domain trie used for wildcard matching.
// "*.example.com" is stored as com → example → * (wildcard sentinel).
type trieNode struct {
	children map[string]*trieNode
	terminal bool // true if a wildcard pattern ends at this node
}

// Blocklist holds domains that the proxy should refuse to connect to.
// Entries support exact match ("example.com") and leading-wildcard ("*.example.com").
// A wildcard entry also matches all subdomains at any depth.
type Blocklist struct {
	exact map[string]struct{}
	trie  *trieNode
}

// NewBlocklist builds a Blocklist from a slice of domain strings.
// Each entry is either an exact domain ("example.com") or a wildcard ("*.example.com").
func NewBlocklist(domains []string) *Blocklist {
	bl := &Blocklist{
		exact: make(map[string]struct{}),
		trie:  &trieNode{children: make(map[string]*trieNode)},
	}
	for _, d := range domains {
		addEntry(bl, d)
	}
	return bl
}

func addEntry(bl *Blocklist, line string) {
	line = strings.ToLower(strings.TrimSpace(line))
	if line == "" {
		return
	}
	if strings.HasPrefix(line, "*.") {
		// Insert reversed labels of the base domain, then a wildcard sentinel "*".
		// "*.example.com" → labels ["com","example"], sentinel "*"
		base := line[2:] // "example.com"
		labels := strings.Split(base, ".")
		node := bl.trie
		for i := len(labels) - 1; i >= 0; i-- {
			node = getOrCreate(node, labels[i])
		}
		// "*" sentinel marks that any subdomain below this node is blocked.
		node = getOrCreate(node, "*")
		node.terminal = true
	} else {
		bl.exact[line] = struct{}{}
	}
}

func getOrCreate(n *trieNode, label string) *trieNode {
	if n.children == nil {
		n.children = make(map[string]*trieNode)
	}
	if child, ok := n.children[label]; ok {
		return child
	}
	child := &trieNode{children: make(map[string]*trieNode)}
	n.children[label] = child
	return child
}

// IsBlocked reports whether host (with or without port) is on the blocklist.
func (bl *Blocklist) IsBlocked(host string) bool {
	if bl == nil {
		return false
	}
	h := strings.ToLower(host)
	if stripped, _, err := net.SplitHostPort(h); err == nil {
		h = stripped
	}

	if _, ok := bl.exact[h]; ok {
		return true
	}
	return bl.wildcardBlocked(h)
}

// wildcardBlocked walks the trie with reversed labels of h.
// It returns true when it finds a "*" terminal that matches h as a subdomain.
func (bl *Blocklist) wildcardBlocked(h string) bool {
	labels := strings.Split(h, ".")
	node := bl.trie
	// Traverse from the TLD inward (reversed label order).
	for i := len(labels) - 1; i >= 0; i-- {
		child, ok := node.children[labels[i]]
		if !ok {
			return false
		}
		node = child
		// If this node has a wildcard sentinel and there are still labels left to
		// consume (i > 0), the remaining path is a subdomain — it's blocked.
		// When i == 0 we've consumed the last label, meaning the host IS the base
		// domain itself (e.g. "example.com"), which *.example.com must not match.
		if wc, ok := node.children["*"]; ok && wc.terminal && i > 0 {
			return true
		}
	}
	return false
}
