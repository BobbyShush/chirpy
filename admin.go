package main

import (
	"fmt"
	"log"
	"net/http"
)

func handlerHealthz(w http.ResponseWriter,r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(200)
	_, err := w.Write([]byte("OK"))
	if err != nil {
		log.Printf("Couldn't write body. Err: %v", err)
	}
}

func (cfg *apiConfig) middlewareMetricsInc(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
		cfg.fileserverHits.Add(1)
		next.ServeHTTP(w, r)
	})
}

func (cfg *apiConfig) handlerMetrics(w http.ResponseWriter,r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	bodyString := fmt.Sprintf(`
<html>
  <body>
    <h1>Welcome, Chirpy Admin</h1>
    <p>Chirpy has been visited %d times!</p>
  </body>
</html>
	`, cfg.fileserverHits.Load())
	_, err := w.Write([]byte(bodyString))
	if err != nil {
		log.Printf("Couldn't write body. Err: %v", err)
	}
}

func (cfg *apiConfig) handlerReset(w http.ResponseWriter,r *http.Request) {
	if cfg.platform != DEV {
		w.WriteHeader(403)
	}

	cfg.fileserverHits.Store(0)

	err := cfg.db.Reset(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		respBody := respErr{Error: "Something went wrong"}
		marshalAndWrite(respBody, w)
		return
	}
}