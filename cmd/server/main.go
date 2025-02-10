package main

import (
	"database/sql"
	"encoding/json"
	"html/template"
	"log"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	"github.com/boxy-pug/chirpy/internal/auth"
	"github.com/boxy-pug/chirpy/internal/database"
	"github.com/boxy-pug/chirpy/internal/utils"
	"github.com/google/uuid"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type apiConfig struct {
	fileserverHits atomic.Int32
	dbQueries      *database.Queries
	platform       string
	tokenSecret    string
}

type User struct {
	ID           uuid.UUID `json:"id"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
	Email        string    `json:"email"`
	Token        string    `json:"token"`
	RefreshToken string    `json:"refresh_token"`
}

type Chirp struct {
	ID        uuid.UUID     `json:"id"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
	Body      string        `json:"body"`
	UserId    uuid.NullUUID `json:"user_id"`
}

type RefreshToken struct {
	Token     string        `json:"token"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
	UserID    uuid.NullUUID `json:"user_id"`
	ExpiresAt time.Time     `json:"expires_at"`
	RevokedAt sql.NullTime  `json:"revoked_at"`
}

func main() {
	godotenv.Load()
	dbURL := os.Getenv("DB_URL")
	platform := os.Getenv("PLATFORM")
	tokenSecret := os.Getenv("JWT_SECRET")

	db, err := sql.Open("postgres", dbURL)
	if err != nil {
		log.Fatalf("error connecting to database: %v", err)
	}
	defer db.Close()

	dbQueries := database.New(db)

	mux := http.NewServeMux()

	apiCfg := &apiConfig{
		dbQueries:   dbQueries,
		platform:    platform,
		tokenSecret: tokenSecret,
	}

	fileServer := http.FileServer(http.Dir("."))

	handler := http.StripPrefix("/app/", fileServer)

	mux.Handle("/app/", apiCfg.middlewareMetricsInc(handler))
	mux.HandleFunc("GET /api/healthz", apiCfg.handleHealthz)
	mux.HandleFunc("GET /admin/metrics", apiCfg.handleMetrics)
	mux.HandleFunc("POST /admin/reset", apiCfg.handleReset)
	mux.HandleFunc("POST /api/chirps", apiCfg.handleCreateChirp)
	mux.HandleFunc("POST /api/users", apiCfg.handleCreateUser)
	mux.HandleFunc("GET /api/chirps", apiCfg.handleGetAllChirps)
	mux.HandleFunc("GET /api/chirps/{chirpID}", apiCfg.handleGetChirp)
	mux.HandleFunc("POST /api/login", apiCfg.handleLogin)
	mux.HandleFunc("POST /api/refresh", apiCfg.handleRefresh)
	mux.HandleFunc("POST /api/revoke", apiCfg.handleRevoke)

	server := &http.Server{
		Addr:    ":8080",
		Handler: mux,
	}

	err = server.ListenAndServe()
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
	if cfg.platform != "dev" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	err := cfg.dbQueries.DeleteAllUsers(r.Context())
	if err != nil {
		log.Printf("error deleting all users: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "could not delete all users")
		return
	}
	w.WriteHeader(http.StatusOK)
}

func (cfg *apiConfig) handleCreateChirp(w http.ResponseWriter, r *http.Request) {

	// Step 1: Get the bearer token from the Authorization header
	tokenString, err := auth.GetBearerToken(r.Header)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "missing or invalid token")
		return
	}

	// Step 2: Validate the token and get the user ID
	userID, err := auth.ValidateJWT(tokenString, cfg.tokenSecret)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "invalid token")
		return
	}
	log.Printf("UserId: %v", userID)

	type parameters struct {
		Body string `json:"body"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err = decoder.Decode(&params)
	if err != nil {
		log.Printf("Error decoding parameters: %s", err)
		utils.RespondWithError(w, http.StatusBadRequest, "Invalid request body")
		return
	}

	if len(params.Body) > 140 {
		utils.RespondWithError(w, http.StatusBadRequest, "Chirp is too long")
		return
	}

	params.Body = utils.BadWordReplacement(params.Body)

	dbChirp, err := cfg.dbQueries.CreateChirp(r.Context(), database.CreateChirpParams{Body: params.Body, UserID: uuid.NullUUID{UUID: userID, Valid: true}})
	if err != nil {
		log.Printf("error creating chirp: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "could not create chirp")
	}

	respBody := Chirp{
		ID:        dbChirp.ID,
		CreatedAt: dbChirp.CreatedAt,
		UpdatedAt: dbChirp.UpdatedAt,
		Body:      dbChirp.Body,
		UserId:    dbChirp.UserID,
	}

	utils.RespondWithJSON(w, http.StatusCreated, respBody)
}

func (cfg *apiConfig) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Fatalf("error decoding params: %v", err)
		utils.RespondWithError(w, http.StatusBadRequest, "could not decode email adress")
	}

	hashedPassword, err := auth.HashPassword(params.Password)
	if err != nil {
		log.Printf("error hashing password: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "could not hash password")
		return
	}

	dbUser, err := cfg.dbQueries.CreateUser(r.Context(), database.CreateUserParams{params.Email, hashedPassword})
	if err != nil {
		log.Printf("error creating user: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "could not create user")
	}
	userResp := User{
		ID:        dbUser.ID,
		CreatedAt: dbUser.CreatedAt,
		UpdatedAt: dbUser.UpdatedAt,
		Email:     dbUser.Email,
	}
	utils.RespondWithJSON(w, http.StatusCreated, userResp)
}

func (cfg *apiConfig) handleGetAllChirps(w http.ResponseWriter, r *http.Request) {
	dbChirps, err := cfg.dbQueries.GetAllChirps(r.Context())
	if err != nil {
		log.Printf("error getting all chirps: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "could retrieve chirps")
		return
	}

	respChirps := make([]Chirp, len(dbChirps))

	for i, dbChirp := range dbChirps {
		respChirps[i] = Chirp{
			ID:        dbChirp.ID,
			CreatedAt: dbChirp.CreatedAt,
			UpdatedAt: dbChirp.UpdatedAt,
			Body:      dbChirp.Body,
			UserId:    dbChirp.UserID,
		}
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(respChirps)
}

func (cfg *apiConfig) handleGetChirp(w http.ResponseWriter, r *http.Request) {
	chirpIdStr := r.PathValue("chirpID")

	chirpId, err := uuid.Parse(chirpIdStr)
	if err != nil {
		http.Error(w, "Invalid Chirp ID", http.StatusBadRequest)
		utils.RespondWithError(w, http.StatusInternalServerError, "couldnt parse chirp id")
		return
	}

	dbChirp, err := cfg.dbQueries.GetChirp(r.Context(), chirpId)
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "couldnt fetch chirp")
		return
	}

	respChirp := Chirp{
		ID:        dbChirp.ID,
		CreatedAt: dbChirp.CreatedAt,
		UpdatedAt: dbChirp.UpdatedAt,
		Body:      dbChirp.Body,
		UserId:    dbChirp.UserID,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	json.NewEncoder(w).Encode(respChirp)

}

func (cfg *apiConfig) handleLogin(w http.ResponseWriter, r *http.Request) {

	type parameters struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}
	decoder := json.NewDecoder(r.Body)
	params := parameters{}
	err := decoder.Decode(&params)
	if err != nil {
		log.Printf("error decoding params: %v", err)
		utils.RespondWithError(w, http.StatusBadRequest, "could not decode email and password")
		return
	}

	user, err := cfg.dbQueries.GetUserByEmail(r.Context(), params.Email)
	if err != nil {
		// Check if the error is due to the user not being found
		if err == sql.ErrNoRows {
			utils.RespondWithError(w, http.StatusUnauthorized, "incorrect email or password")
			return
		}
		log.Printf("error retrieving user: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "could not retrieve user")
		return
	}

	// Check if the hashed password is valid
	err = auth.CheckPasswordHash(user.HashedPassword, params.Password) // Directly use HashedPassword
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "incorrect email or password!!")
		return
	}

	// Create JWT token
	token, err := auth.MakeJWT(user.ID, cfg.tokenSecret)
	if err != nil {
		log.Printf("error creating JWT: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "could not create JWT")
		return
	}

	// Create refresh token
	refreshToken, err := auth.MakeRefreshToken()
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "error making refresh token")
	}

	log.Printf("Generated refresh token: %s", refreshToken)

	log.Printf("Setting refresh token expiry to: %s", time.Now().Add(60*24*time.Hour))

	dbRefreshToken, err := cfg.dbQueries.CreateRefreshToken(r.Context(), database.CreateRefreshTokenParams{
		Token:     refreshToken,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(60 * 24 * time.Hour),
		RevokedAt: sql.NullTime{},
	})
	if err != nil {
		utils.RespondWithError(w, http.StatusInternalServerError, "error creating refresh token")
	}
	log.Printf("dbrefreshtokens: %+v", dbRefreshToken)

	log.Printf("DB-refresh-token: %s, and expiry time: %s", dbRefreshToken.Token, dbRefreshToken.ExpiresAt)

	respUser := User{
		ID:           dbRefreshToken.UserID,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
		Email:        user.Email,
		Token:        token,
		RefreshToken: refreshToken,
	}
	utils.RespondWithJSON(w, http.StatusOK, respUser)

}

func (cfg *apiConfig) handleRefresh(w http.ResponseWriter, r *http.Request) {
	headerRefreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "could not get refresh token from header")
		return
	}
	log.Printf("Incoming refresh token: %s", headerRefreshToken)

	dbRefreshToken, err := cfg.dbQueries.GetRefreshToken(r.Context(), headerRefreshToken)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "could not find refresh token in db")
		return
	}

	log.Printf("dbrefreshtokenfacts: %+v", dbRefreshToken)

	if dbRefreshToken.ExpiresAt.Before(time.Now()) || !dbRefreshToken.RevokedAt.Time.IsZero() {
		utils.RespondWithError(w, http.StatusUnauthorized, "refreshtoken expired")
		return
	}

	// Create JWT token
	token, err := auth.MakeJWT(dbRefreshToken.UserID, cfg.tokenSecret)
	if err != nil {
		log.Printf("error creating JWT: %v", err)
		utils.RespondWithError(w, http.StatusInternalServerError, "could not create JWT")
		return
	}
	log.Printf("token!: %v", token)

	utils.RespondWithJSON(w, http.StatusOK, map[string]string{"token": token})
}

func (cfg *apiConfig) handleRevoke(w http.ResponseWriter, r *http.Request) {
	headerRefreshToken, err := auth.GetBearerToken(r.Header)
	if err != nil {
		utils.RespondWithError(w, http.StatusBadRequest, "could not get refresh token from header")
		return
	}

	rowsAffected, err := cfg.dbQueries.RevokeRefreshToken(r.Context(), headerRefreshToken)
	if err != nil {
		utils.RespondWithError(w, http.StatusUnauthorized, "could not revoke refresh token")
		return
	}

	if rowsAffected == 0 {
		utils.RespondWithError(w, http.StatusUnauthorized, "refresh token not found or already revoked")
	}

	utils.RespondWithJSON(w, http.StatusNoContent, nil) // 204 No Content
}
