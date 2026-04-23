package scan

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Path constants for the proxy's internal scan endpoints.
const (
	PathPrefix   = "/scan/"
	PathStatus   = PathPrefix + "status"
	PathDownload = PathPrefix + "download"
)

// Handler serves the /scan/ internal endpoints.
type Handler struct {
	manager *Manager
}

// NewHandler creates a Handler backed by the given Manager.
func NewHandler(m *Manager) *Handler {
	return &Handler{manager: m}
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Allow fetch() from file:// only (Origin: null).
	// Wildcard would let any webpage on the LAN poll scan results.
	w.Header().Set("Access-Control-Allow-Origin", "null")
	w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	switch r.URL.Path {
	case PathStatus:
		h.handleStatus(w, r)
	case PathDownload:
		h.handleDownload(w, r)
	default:
		http.NotFound(w, r)
	}
}

// handleStatus returns a JSON status object for the given job ID.
func (h *Handler) handleStatus(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	job, ok := h.manager.GetJob(id)
	if !ok {
		http.NotFound(w, r)
		return
	}

	type statusResp struct {
		Status string `json:"status"`
		Threat string `json:"threat,omitempty"`
	}

	resp := statusResp{}
	switch job.Status() {
	case StatusPending:
		resp.Status = "pending"
	case StatusScanning:
		resp.Status = "scanning"
	case StatusClean:
		resp.Status = "clean"
	case StatusInfected:
		resp.Status = "infected"
		resp.Threat = job.ThreatName()
	case StatusTooLarge:
		resp.Status = "toobig"
	default:
		resp.Status = "error"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp) //nolint:errcheck
}

// handleDownload serves the buffered temp file for clean (or error) jobs.
func (h *Handler) handleDownload(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Query().Get("id")
	job, ok := h.manager.GetJob(id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !h.manager.ServeFile(job, w, r) {
		http.Error(w, "ファイルは利用できません", http.StatusForbidden)
	}
}

// RenderScanPage returns the HTML delivered to the browser as a downloadable file.
// proxyAddr is the externally reachable proxy address (e.g. "http://192.168.1.1:8080").
func RenderScanPage(jobID, filename, proxyAddr string) string {
	statusURL := proxyAddr + PathStatus + "?id=" + jobID
	downloadURL := proxyAddr + PathDownload + "?id=" + jobID
	return fmt.Sprintf(scanPageTemplate,
		filename,
		fmt.Sprintf("%q", statusURL),
		fmt.Sprintf("%q", downloadURL),
		fmt.Sprintf("%q", filename),
	)
}

const scanPageTemplate = `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>ファイル解析中 — %s</title>
  <style>
    *{box-sizing:border-box}
    body{font-family:sans-serif;display:flex;justify-content:center;align-items:center;
         min-height:100vh;margin:0;background:#f0f2f5}
    .card{background:#fff;border-radius:12px;padding:48px 56px;
          box-shadow:0 4px 16px rgba(0,0,0,.1);text-align:center;max-width:540px;width:100%%}
    .spinner{width:52px;height:52px;border:5px solid #e0e0e0;border-top-color:#1a73e8;
             border-radius:50%%;animation:spin .9s linear infinite;margin:0 auto 20px}
    @keyframes spin{to{transform:rotate(360deg)}}
    h1{font-size:1.3rem;margin:0 0 10px;color:#202124}
    .sub{color:#5f6368;font-size:.95rem;margin:0}
    .filename{color:#3c4043;font-size:.9rem;font-weight:500;margin:0 0 8px;word-break:break-all}
    .btn{display:inline-block;margin-top:24px;padding:11px 28px;background:#1a73e8;
         color:#fff;border-radius:6px;text-decoration:none;font-size:1rem;font-weight:500}
    .btn:hover{background:#1558b0}
    .threat{color:#d93025;font-weight:500}
    .icon{font-size:2.5rem;margin-bottom:12px}
  </style>
</head>
<body>
<div class="card" id="card">
  <div class="spinner" id="spinner"></div>
  <h1 id="title">ファイルを解析中...</h1>
  <p class="filename" id="filename"></p>
  <p class="sub" id="msg">ウイルススキャンが完了するまでお待ちください。</p>
</div>
<script>
(function(){
  var statusURL  = %s;
  var downloadURL = %s;
  var filename   = %s;

  document.getElementById('filename').textContent = filename;

  function poll() {
    fetch(statusURL)
      .then(function(r){ return r.json(); })
      .then(function(data){
        if (data.status === 'clean') {
          document.getElementById('spinner').style.display = 'none';
          document.getElementById('title').textContent = '解析完了';
          document.getElementById('msg').innerHTML =
            '<a class="btn" href="' + downloadURL + '" download="' + filename + '">ダウンロード</a>';
        } else if (data.status === 'infected') {
          document.getElementById('spinner').style.display = 'none';
          document.getElementById('card').insertAdjacentHTML(
            'afterbegin', '<div class="icon">⛔</div>');
          document.getElementById('title').textContent = '脅威を検出しました';
          document.getElementById('msg').innerHTML =
            '<span class="threat">検出: ' + data.threat + '</span><br>' +
            '<span>このファイルはダウンロードできません。</span>';
        } else if (data.status === 'error') {
          document.getElementById('spinner').style.display = 'none';
          document.getElementById('title').textContent = 'スキャン不可';
          document.getElementById('msg').innerHTML =
            'スキャンをスキップしました。<br>' +
            '<a class="btn" href="' + downloadURL + '" download="' + filename + '">ダウンロード</a>';
        } else if (data.status === 'toobig') {
          document.getElementById('spinner').style.display = 'none';
          document.getElementById('card').insertAdjacentHTML(
            'afterbegin', '<div class="icon">⚠️</div>');
          document.getElementById('title').textContent = 'ファイルが大きすぎます';
          document.getElementById('msg').textContent =
            'ファイルが大きすぎてスキャンできません。';
        } else {
          setTimeout(poll, 2000);
        }
      })
      .catch(function(){ setTimeout(poll, 3000); });
  }
  poll();
})();
</script>
</body>
</html>`
