package main

import (
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"sync/atomic"
)

type apiConfig struct {
	fileserverHits atomic.Int32
}

func main() {
	mux := http.NewServeMux()

	apiCfg := &apiConfig{}

	fileServer := http.FileServer(http.Dir("."))

	handler := http.StripPrefix("/app/", fileServer)

	mux.Handle("/app/", apiCfg.middlewareMetricsInc(handler))
	mux.HandleFunc("GET /api/healthz", apiCfg.handleHealthz)
	mux.HandleFunc("GET /admin/metrics", apiCfg.handleMetrics)
	mux.HandleFunc("POST /admin/reset", apiCfg.handleReset)
	mux.HandleFunc("POST /api/validate_chirp", apiCfg.handleValidateChirp)

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	err := server.ListenAndServe()
	if err != nil {
		panic(err)
	}
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK\n"))
}

func (cfg *apiConfig) handleMetrics(w http.ResponseWriter, r *http.Request) {
	hits := cfg.fileserverHits.Load()
	const htmlTemplate = `
<!DOCTYPE html>
<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited {{.}} times!</p>
  </body>
</html>
`

	t, err := template.New("metrics").Parse(htmlTemplate)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	err = t.Execute(w, hits)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
	}
}

func (cfg *apiConfig) handleReset(w http.ResponseWriter, r *http.Request) {
	cfg.fileserverHits.Store(0)
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Hits reset to 0"))
}

func (cfg *apiConfig) handleValidateChirp(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Body string `json:"body"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		w.WriteHeader(500)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid request body"})
		return
	}

	type returnVals struct {
		Error string `json:"error, omitempty"`
		Valid bool   `json:"valid, omitempty"`
	}

	respBody := returnVals{}

	if len(params.Body) > 140 {
		respBody.Error = "Chirp is too long"
		w.WriteHeader(400)
		json.NewEncoder(w).Encode(respBody)
		return
	}

	respBody.Valid = true

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	json.NewEncoder(w).Encode(respBody)
}
