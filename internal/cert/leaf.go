package cert

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"sync/atomic"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	redisKeyPrefix          = "leafcert:"
	memCacheMax             = 2000
	memCacheCleanupInterval = 10 * time.Minute
)

type memEntry struct {
	cert      *tls.Certificate
	expiresAt time.Time
}

type Cache struct {
	ca       *CA
	redis    *redis.Client
	memCache sync.Map     // domain → *memEntry
	memCount atomic.Int64
}

type cachedCert struct {
	CertPEM      string `json:"cert_pem"`
	KeyPEM       string `json:"key_pem"`
	NotAfterUnix int64  `json:"not_after_unix"`
}

func NewCache(ctx context.Context, ca *CA, rdb *redis.Client) *Cache {
	c := &Cache{ca: ca, redis: rdb}
	go c.runCleanup(ctx)
	return c
}

func (c *Cache) runCleanup(ctx context.Context) {
	ticker := time.NewTicker(memCacheCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			c.evictExpired()
		}
	}
}

func (c *Cache) evictExpired() {
	now := time.Now()
	c.memCache.Range(func(k, v any) bool {
		if v.(*memEntry).expiresAt.Before(now) {
			c.memCache.Delete(k)
			c.memCount.Add(-1)
		}
		return true
	})
}

func (c *Cache) storeMem(domain string, cert *tls.Certificate, notAfter time.Time) {
	if c.memCount.Load() >= memCacheMax {
		return
	}
	c.memCache.Store(domain, &memEntry{
		cert:      cert,
		expiresAt: notAfter,
	})
	c.memCount.Add(1)
}

func (c *Cache) GetCert(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	domain := hello.ServerName
	if domain == "" {
		domain = "localhost"
	}

	// 1. In-process cache: skip Redis and PEM parsing on cache hit.
	if v, ok := c.memCache.Load(domain); ok {
		e := v.(*memEntry)
		if time.Now().Add(24 * time.Hour).Before(e.expiresAt) {
			return e.cert, nil
		}
		c.memCache.Delete(domain)
		c.memCount.Add(-1)
	}

	ctx := hello.Context()
	key := redisKeyPrefix + domain

	// 2. Redis cache.
	data, err := c.redis.Get(ctx, key).Bytes()
	if err != nil && !errors.Is(err, redis.Nil) {
		slog.Warn("redis get cert", "domain", domain, "err", err)
	}
	if err == nil {
		cc, err := decodeCachedCert(data)
		if err != nil {
			slog.Warn("decode cached cert", "domain", domain, "err", err)
		} else if time.Now().Add(24 * time.Hour).Before(time.Unix(cc.NotAfterUnix, 0)) {
			cert, err := cc.toTLS()
			if err != nil {
				return nil, err
			}
			c.storeMem(domain, cert, time.Unix(cc.NotAfterUnix, 0))
			return cert, nil
		}
		c.redis.Del(ctx, key)
	}

	// 3. Generate new certificate.
	generated, err := c.generate(domain)
	if err != nil {
		return nil, err
	}

	c.saveToRedis(ctx, key, generated)
	c.storeMem(domain, &generated.cert, generated.notAfter)

	return &generated.cert, nil
}

func (c *Cache) saveToRedis(ctx context.Context, key string, g *generatedCert) {
	ttl := time.Until(g.notAfter) - 24*time.Hour
	if ttl <= 0 {
		return
	}
	payload := cachedCert{
		CertPEM:      string(g.certPEM),
		KeyPEM:       string(g.keyPEM),
		NotAfterUnix: g.notAfter.Unix(),
	}
	data, err := json.Marshal(payload)
	if err != nil {
		slog.Warn("marshal cert for redis", "err", err)
		return
	}
	if err := c.redis.Set(ctx, key, data, ttl).Err(); err != nil {
		slog.Warn("redis set cert", "key", key, "err", err)
	}
}

func decodeCachedCert(data []byte) (*cachedCert, error) {
	var cc cachedCert
	if err := json.Unmarshal(data, &cc); err != nil {
		return nil, err
	}
	return &cc, nil
}

func (cc *cachedCert) toTLS() (*tls.Certificate, error) {
	cert, err := tls.X509KeyPair([]byte(cc.CertPEM), []byte(cc.KeyPEM))
	if err != nil {
		return nil, fmt.Errorf("parse cached cert: %w", err)
	}
	return &cert, nil
}

func (c *Cache) TLSConfig() *tls.Config {
	return &tls.Config{
		GetCertificate: c.GetCert,
		MinVersion:     tls.VersionTLS12,
		// CipherSuites applies to TLS 1.2 only; TLS 1.3 suites are fixed by the spec.
		// Only ECDHE + AEAD suites: forward secrecy, no CBC/RC4/3DES.
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
		},
	}
}

type generatedCert struct {
	cert     tls.Certificate
	certPEM  []byte
	keyPEM   []byte
	notAfter time.Time
}

func (c *Cache) generate(domain string) (*generatedCert, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate leaf key for %s: %w", domain, err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	now := time.Now()
	notAfter := now.Add(365 * 24 * time.Hour)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		DNSNames:     []string{domain},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, c.ca.Cert, &key.PublicKey, c.ca.Key)
	if err != nil {
		return nil, fmt.Errorf("create leaf cert for %s: %w", domain, err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}

	return &generatedCert{cert: tlsCert, certPEM: certPEM, keyPEM: keyPEM, notAfter: notAfter}, nil
}

// CACertPEM returns the PEM-encoded CA certificate used for MITM.
func (c *Cache) CACertPEM() []byte { return c.ca.CertPEM }

// CACertDER returns the DER-encoded CA certificate (raw ASN.1 bytes).
func (c *Cache) CACertDER() []byte {
	block, _ := pem.Decode(c.ca.CertPEM)
	if block == nil {
		return nil
	}
	return block.Bytes
}
