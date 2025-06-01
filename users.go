package main

import (
	"bootdev/chirpy/internal/auth"
	"bootdev/chirpy/internal/database"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
)

type User struct {
	ID        		uuid.UUID	`json:"id"`
	CreatedAt 		time.Time	`json:"created_at"`
	UpdatedAt 		time.Time	`json:"updated_at"`
	Email     		string		`json:"email"`
	Token			string		`json:"token"`
	RefreshToken	string		`json:"refresh_token"`
	IsChirpyRed		bool		`json:"is_chirpy_red"`
}

type ExpectedReq struct {
	Password 			string 	`json:"password"`
	Email				string	`json:"email"`
}

func (cfg *apiConfig) handlerCreateUser(w http.ResponseWriter,r *http.Request){
	expectedReq, err := decodeUserReq(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		respBody := respErr{Error: "Couldn't decode JSON"}
		marshalAndWrite(respBody, w)
		return
	}

	if expectedReq.Password == "" {
		w.WriteHeader(400)
		return
	}

	hashedPassword, err := auth.HashPassword(expectedReq.Password)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		respBody := respErr{Error: "Failed hashing password"}
		marshalAndWrite(respBody, w)
		return
	}

	params := database.CreateUserParams{
		HashedPassword: hashedPassword,
		Email: expectedReq.Email,
	}
	user, err := cfg.db.CreateUser(r.Context(), params)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(500)
		respBody := respErr{Error: "Couldn't create user in database"}
		marshalAndWrite(respBody, w)
		return
	}
	userResp := User{
		ID: user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email: user.Email,
		IsChirpyRed: user.IsChirpyRed,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(201)
	marshalAndWrite(userResp, w)
}

func (cfg *apiConfig) handlerLogin(w http.ResponseWriter, r *http.Request) {
	expectedReq, err := decodeUserReq(r)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(400)
		respBody := respErr{Error: "Couldn't decode JSON"}
		marshalAndWrite(respBody, w)
		return
	}

	user, err := cfg.db.GetUser(r.Context(), expectedReq.Email)
	if err != nil {
		w.WriteHeader(401)
		return
	}

	err = auth.CheckPasswordHash(user.HashedPassword, expectedReq.Password)
	if err != nil {
		w.WriteHeader(401)
		return
	}

	tokenString, err := auth.MakeJWT(user.ID, cfg.secret, 1 * time.Hour)
	if err != nil {
		w.WriteHeader(401)
		return
	}

	rTokenString, err := cfg.createRefreshToken(r.Context(), user.ID)
	if err != nil {
		w.WriteHeader(500)
		return
	}
	
	userResp := User{
		ID: user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email: user.Email,
		Token: tokenString,
		RefreshToken: rTokenString,
		IsChirpyRed: user.IsChirpyRed,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	marshalAndWrite(userResp, w)
}

func decodeUserReq(r *http.Request) (ExpectedReq, error) {
	var expectedReq ExpectedReq
	decoder := json.NewDecoder(r.Body)
	err := decoder.Decode(&expectedReq)
	if err != nil {
		return ExpectedReq{}, err
	}
	return expectedReq, nil
}

func (cfg *apiConfig) createRefreshToken(c context.Context, userID uuid.UUID) (string, error) {
	const refreshTokenValidity = 60 * (24 * time.Hour)
	rTokenString, err := auth.MakeRefreshToken()
	if err != nil {
		return "", err
	}
	params := database.CreateRefreshTokenParams{
		Token: rTokenString,
		UserID: userID,
		ExpiresAt: time.Now().Add(refreshTokenValidity),
	}
	_, err = cfg.db.CreateRefreshToken(c, params)
	if err != nil {
		return "", err
	}
	return rTokenString, nil
}

func (cfg *apiConfig) handlerRefresh(w http.ResponseWriter, r *http.Request) {
	rTokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		w.WriteHeader(401)
		return
	}
	refreshToken, err := cfg.db.GetRefreshToken(r.Context(), rTokenString)
	if err != nil || !isRefreshTokenValid(refreshToken) {
		w.WriteHeader(401)
		return
	}

	user, err := cfg.db.GetUserFromRefreshToken(r.Context(), rTokenString)
	if err != nil {
		w.WriteHeader(401)
		return
	}
	jwtTokenString, err := auth.MakeJWT(user.ID.UUID, cfg.secret, 1 * time.Hour)
	if err != nil {
		w.WriteHeader(401)
		return
	}

	type RespBody struct{
		Token	string	`json:"token"`
	}
	respBody := RespBody{Token: jwtTokenString}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	marshalAndWrite(respBody, w)
}

func isExpired(expiresAt time.Time) bool {
	/* Time.Compare returns 0 if the two values are equal
	Which means that this will only return true if the 
	expiresAt time.Time is before time.Now()*/
	return expiresAt.Compare(time.Now()) == -1
}

func isRefreshTokenValid(refreshToken database.RefreshToken) bool {
	return !(isExpired(refreshToken.ExpiresAt) || refreshToken.RevokedAt.Valid)
}

func (cfg *apiConfig) handlerRevoke(w http.ResponseWriter, r *http.Request) {
	rTokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		w.WriteHeader(401)
		return
	}

	err = cfg.db.Revoke(r.Context(), rTokenString)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			// To prevent token probing
			w.WriteHeader(204)
			return
		}
		w.WriteHeader(500)
		return
	}

	w.WriteHeader(204)
}

func (cfg *apiConfig) handlerUpdateUser(w http.ResponseWriter, r *http.Request) {
	userID, err := cfg.authenticate(r)
	if err != nil {
		w.WriteHeader(401)
		return
	}

	reqData, err := decodeUserReq(r)
	if err != nil {
		w.WriteHeader(401)
		return
	}

	hashedPw, err := auth.HashPassword(reqData.Password)
	if err != nil {
		w.WriteHeader(401)
		return
	}

	params := database.UpdateUserParams{
		HashedPassword: hashedPw,
		Email: reqData.Email,
		ID: userID,
	}
	user, err := cfg.db.UpdateUser(r.Context(), params)
	if err != nil {
		w.WriteHeader(500)
		return
	}

	userResp := User{
		ID: user.ID,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
		Email: user.Email,
		IsChirpyRed: user.IsChirpyRed,
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	marshalAndWrite(userResp, w)
}

func (cfg *apiConfig) handlerUpgradeRed(w http.ResponseWriter, r *http.Request) {
	apiKey, err := auth.GetAPIKey(r.Header)
	if err != nil || apiKey != cfg.polkaKey {
		w.WriteHeader(401)
		return
	}

	type DataStruct struct {
		UserID	string		`json:"user_id"`
	}
	type ExpectedReq struct {
		Event	string		`json:"event"`
		Data	DataStruct	`json:"data"`
	}
	var expectedReq ExpectedReq
	decoder := json.NewDecoder(r.Body)
	err = decoder.Decode(&expectedReq)
	if err != nil {
		w.WriteHeader(400)
		return
	}

	const userUpdgraded = "user.upgraded"
	if expectedReq.Event != userUpdgraded {
		w.WriteHeader(204)
		return
	}

	id, err := uuid.Parse(expectedReq.Data.UserID)
	if err != nil {
		w.WriteHeader(400)
		return
	}

	_, err = cfg.db.UpgradeUserRed(r.Context(), id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows){
			w.WriteHeader(404)
			return
		}
		w.WriteHeader(500)
		return
	}

	w.WriteHeader(204)
}