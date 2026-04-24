package api

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// NewHandler builds the HTTP mux for the API server.
// apiKey is the expected bearer token; empty string disables auth.
func NewHandler(store *Store, apiKey string) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	mux.HandleFunc("GET /api/v1/blocklist", handleList(store))
	mux.HandleFunc("POST /api/v1/blocklist", handleAdd(store))
	mux.HandleFunc("PATCH /api/v1/blocklist/{domain}", handleUpdate(store))
	mux.HandleFunc("DELETE /api/v1/blocklist/{domain}", handleRemove(store))
	mux.HandleFunc("GET /api/v1/blocklist/{domain}/audit", handleAudit(store))

	mux.HandleFunc("GET /api/v1/scan/settings", handleGetScanSettings(store))
	mux.HandleFunc("PATCH /api/v1/scan/settings", handlePatchScanSetting(store))
	mux.HandleFunc("GET /api/v1/scan/mime-types", handleListMimeTypes(store))
	mux.HandleFunc("PATCH /api/v1/scan/mime-types/{pattern}", handlePatchMimeType(store))

	if apiKey == "" {
		return mux
	}
	return bearerAuth(apiKey, mux)
}

func bearerAuth(apiKey string, h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			h.ServeHTTP(w, r)
			return
		}
		token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
		if !ok || token != apiKey {
			jsonError(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func handleList(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		lq := ListQuery{
			Q:     q.Get("q"),
			Sort:  q.Get("sort"),
			Order: q.Get("order"),
			Page:  queryInt(q, "page"),
			Limit: queryInt(q, "limit"),
		}
		result, err := store.List(r.Context(), q.Get("enabled") == "true", lq)
		if err != nil {
			slog.Error("blocklist list", "err", err)
			jsonError(w, "internal error", http.StatusInternalServerError)
			return
		}
		jsonOK(w, result)
	}
}

func handleAdd(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Domain  string `json:"domain"`
			Comment string `json:"comment"`
			Actor   string `json:"actor"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonError(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		domain := strings.ToLower(strings.TrimSpace(body.Domain))
		if domain == "" {
			jsonError(w, "domain is required", http.StatusBadRequest)
			return
		}

		entry, err := store.Add(r.Context(), domain, body.Comment, body.Actor)
		if err != nil {
			if errors.Is(err, ErrDuplicate) {
				jsonError(w, "domain already exists", http.StatusConflict)
				return
			}
			slog.Error("blocklist add", "domain", domain, "err", err)
			jsonError(w, "internal error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(entry) //nolint:errcheck
	}
}

func handleUpdate(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		domain, err := pathDomain(r)
		if err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}

		var body struct {
			Enabled *bool   `json:"enabled"`
			Comment *string `json:"comment"`
			Actor   string  `json:"actor"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonError(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Enabled == nil && body.Comment == nil {
			jsonError(w, "at least one of enabled or comment is required", http.StatusBadRequest)
			return
		}

		entry, err := store.Update(r.Context(), domain, UpdateRequest{
			Enabled: body.Enabled,
			Comment: body.Comment,
			Actor:   body.Actor,
		})
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				jsonError(w, "domain not found", http.StatusNotFound)
				return
			}
			slog.Error("blocklist update", "domain", domain, "err", err)
			jsonError(w, "internal error", http.StatusInternalServerError)
			return
		}
		jsonOK(w, entry)
	}
}

func handleRemove(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		domain, err := pathDomain(r)
		if err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}

		var body struct {
			Actor   string `json:"actor"`
			Comment string `json:"comment"`
		}
		// body is optional for DELETE; ignore decode errors
		json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck

		if err := store.Remove(r.Context(), domain, body.Actor, body.Comment); err != nil {
			if errors.Is(err, ErrNotFound) {
				jsonError(w, "domain not found", http.StatusNotFound)
				return
			}
			slog.Error("blocklist remove", "domain", domain, "err", err)
			jsonError(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func handleAudit(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		domain, err := pathDomain(r)
		if err != nil {
			jsonError(w, err.Error(), http.StatusBadRequest)
			return
		}

		q := r.URL.Query()
		lq := ListQuery{
			Page:  queryInt(q, "page"),
			Limit: queryInt(q, "limit"),
		}
		result, err := store.AuditLog(r.Context(), domain, lq)
		if err != nil {
			slog.Error("blocklist audit", "domain", domain, "err", err)
			jsonError(w, "internal error", http.StatusInternalServerError)
			return
		}
		jsonOK(w, result)
	}
}

func pathDomain(r *http.Request) (string, error) {
	encoded := r.PathValue("domain")
	d, err := url.PathUnescape(encoded)
	if err != nil {
		return "", errors.New("invalid domain encoding")
	}
	d = strings.ToLower(strings.TrimSpace(d))
	if d == "" {
		return "", errors.New("domain is required")
	}
	return d, nil
}

func queryInt(q url.Values, key string) int {
	n, _ := strconv.Atoi(q.Get(key))
	return n
}

func jsonOK(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg}) //nolint:errcheck
}

// ── Scan settings ─────────────────────────────────────────────────────────────

func handleGetScanSettings(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		entries, err := store.GetScanSettings(r.Context())
		if err != nil {
			slog.Error("scan settings get", "err", err)
			jsonError(w, "internal error", http.StatusInternalServerError)
			return
		}
		if entries == nil {
			entries = []ScanSettingEntry{}
		}
		jsonOK(w, entries)
	}
}

func handlePatchScanSetting(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Key   string `json:"key"`
			Value string `json:"value"`
			Actor string `json:"actor"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonError(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Key == "" || body.Value == "" {
			jsonError(w, "key and value are required", http.StatusBadRequest)
			return
		}

		if err := store.UpdateScanSetting(r.Context(), body.Key, body.Value, body.Actor); err != nil {
			if errors.Is(err, ErrNotFound) {
				jsonError(w, "setting key not found", http.StatusNotFound)
				return
			}
			slog.Error("scan settings update", "key", body.Key, "err", err)
			jsonError(w, "internal error", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func handleListMimeTypes(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		lq := ListQuery{
			Q:     q.Get("q"),
			Sort:  q.Get("sort"),
			Order: q.Get("order"),
		}
		entries, err := store.ListMimeTypes(r.Context(), q.Get("enabled") == "true", lq)
		if err != nil {
			slog.Error("scan mime-types list", "err", err)
			jsonError(w, "internal error", http.StatusInternalServerError)
			return
		}
		if entries == nil {
			entries = []MimeTypeEntry{}
		}
		jsonOK(w, entries)
	}
}

func handlePatchMimeType(store *Store) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		encoded := r.PathValue("pattern")
		pattern, err := url.PathUnescape(encoded)
		if err != nil || strings.TrimSpace(pattern) == "" {
			jsonError(w, "invalid pattern", http.StatusBadRequest)
			return
		}

		var body struct {
			Enabled *bool  `json:"enabled"`
			Note    string `json:"note"`
			Actor   string `json:"actor"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			jsonError(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if body.Enabled == nil && body.Note == "" {
			jsonError(w, "at least one of enabled or note is required", http.StatusBadRequest)
			return
		}

		entry, err := store.UpdateMimeType(r.Context(), pattern, body.Enabled, body.Note, body.Actor)
		if err != nil {
			if errors.Is(err, ErrNotFound) {
				jsonError(w, "pattern not found", http.StatusNotFound)
				return
			}
			slog.Error("scan mime-type update", "pattern", pattern, "err", err)
			jsonError(w, "internal error", http.StatusInternalServerError)
			return
		}
		jsonOK(w, entry)
	}
}
