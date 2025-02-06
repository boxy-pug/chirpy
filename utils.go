package main

import (
	"encoding/json"
	"net/http"
	"strings"
)

func badWordReplacement(s string) string {
	badWords := make(map[string]struct{})
	res := ""

	badWords["kerfuffle"] = struct{}{}
	badWords["sharbert"] = struct{}{}
	badWords["fornax"] = struct{}{}

	wordList := strings.Split(s, " ")
	for _, word := range wordList {
		_, exists := badWords[strings.ToLower(word)]
		if exists {
			res += "****"
			res += " "
		} else {
			res += word
			res += " "
		}

	}
	return res[:len(res)-1]
}

func respondWithError(w http.ResponseWriter, code int, msg string) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func respondWithJSON(w http.ResponseWriter, code int, payload interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(payload)
}
