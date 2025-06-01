package main

import (
	"bootdev/chirpy/internal/auth"
	"bootdev/chirpy/internal/database"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
)

type Chirp struct {
	ID        uuid.UUID `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
	Body      string	`json:"body"`
	UserID    uuid.UUID	`json:"user_id"`
}

func (cfg *apiConfig) handlerCreateChirp(w http.ResponseWriter,r *http.Request) {
	userID, err := cfg.authenticate(r)
	if err != nil {
		w.WriteHeader(401)
		return
	}

	var chp Chirp
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&chp)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		respBody := respErr{Error: "Something went wrong"}
		marshalAndWrite(respBody, w)
		return
	}


	if len(chp.Body) > 140 {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		respBody := respErr{Error: "Chirp is too long"}
		marshalAndWrite(respBody, w)
		return
	}

	chp.cleanChirp()
	params := database.CreateChirpParams{
		Body: chp.Body,
		UserID: userID,
	}
	chpResp, err := cfg.db.CreateChirp(r.Context(), params)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		respBody := respErr{Error: fmt.Sprintf("Couldn't create chirp. Err: %v", err)}
		marshalAndWrite(respBody, w)
		return
	}
	chp = Chirp{
		ID: 		chpResp.ID,
		CreatedAt: 	chpResp.CreatedAt,
		UpdatedAt: 	chpResp.UpdatedAt,
		Body: 		chpResp.Body,
		UserID: 	chpResp.UserID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	marshalAndWrite(chp, w)
}

func marshalAndWrite(respBody any, w http.ResponseWriter) {
	dat, errM := json.Marshal(respBody)
	if errM != nil {
		log.Printf("Error marshalling JSON: %s", errM)
		return
	}

	_, errW := w.Write(dat)
	if errW != nil {
		log.Printf("Couldn't write body. Err: %v", errW)
		return
	}
}

func (chp *Chirp) cleanChirp() {
	profanities := []string{"kerfuffle", "sharbert", "fornax"}
	splitChirp := strings.Split(chp.Body, " ")
	for _, badWord := range profanities {
		for i, word := range splitChirp {
			if strings.ToLower(word) == badWord {
				splitChirp[i] = "****"
			}
		}
	}
	chp.Body = strings.Join(splitChirp, " ")
}

func (cfg *apiConfig) authenticate(r *http.Request) (uuid.UUID, error) {
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		return uuid.UUID{}, err
	}
	userID, err := auth.ValidateJWT(tokenString, cfg.secret)
	if err != nil {
		return uuid.UUID{}, err
	}
	return userID, nil
}

func (cfg *apiConfig) handlerGetChirps(w http.ResponseWriter,r *http.Request) {
	chirps, err := cfg.db.GetChirps(r.Context())
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		respBody := respErr{Error: "Something went wrong"}
		marshalAndWrite(respBody, w)
		return
	}

	responseArr := make([]Chirp, len(chirps))
	for i, chirp := range chirps {
		chp := Chirp{
			ID: chirp.ID,
			CreatedAt: chirp.CreatedAt,
			UpdatedAt: chirp.UpdatedAt,
			Body: chirp.Body,
			UserID: chirp.UserID,
		}
		responseArr[i] = chp
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	marshalAndWrite(responseArr, w)
}

func (cfg *apiConfig) handlerGetChirpSingleton(w http.ResponseWriter,r *http.Request) {
	chirpID := r.PathValue("chirpID")
	id, err := uuid.Parse(chirpID)
	if err != nil {
		w.WriteHeader(400)
		return
	}

	chirp, err := cfg.db.GetChirp(r.Context(), id)
	if err != nil {
		w.WriteHeader(404)
		return
	}
	chp := Chirp{
		ID: chirp.ID,
		CreatedAt: chirp.CreatedAt,
		UpdatedAt: chirp.UpdatedAt,
		Body: chirp.Body,
		UserID: chirp.UserID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	marshalAndWrite(chp, w)
}