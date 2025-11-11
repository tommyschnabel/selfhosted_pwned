package main

import (
	"crypto/sha1"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

type CheckResponse struct {
	Prefix string `json:"prefix"`
	Found  bool   `json:"found"`
	Count  int    `json:"count,omitempty"`
	Error  string `json:"error,omitempty"`
}

func main() {
	port := flag.String("port", "8080", "Port to listen on")
	flag.Parse()

	http.HandleFunc("/api/check/password", handleCheckPassword)
	http.HandleFunc("/api/check/hash", handleCheckHash)

	fs := http.FileServer(http.Dir("./dist"))
	http.Handle("/", fs)

	addr := fmt.Sprintf(":%s", *port)
	log.Printf("Server starting on %s", addr)
	if err := http.ListenAndServe(addr, nil); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

func handleCheckPassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Password string `json:"password"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	if request.Password == "" {
		http.Error(w, "Password not provided", http.StatusBadRequest)
		return
	}

	// Hash the password
	hash := hashPassword(request.Password)
	if hash == "" {
		http.Error(w, "Could not hash password", http.StatusInternalServerError)
		return
	}

	prefix := strings.ToLower(hash)[:5]
	suffixCount, err := checkHashInPwned(prefix, hash)

	response := CheckResponse{
		Prefix: prefix,
	}

	if err != nil {
		response.Error = err.Error()
	} else {
		response.Found = suffixCount > 0
		response.Count = suffixCount
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func handleCheckHash(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var request struct {
		Hash string `json:"hash"`
	}

	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		http.Error(w, "Invalid request body", http.StatusBadRequest)
		return
	}

	hash := strings.ToLower(request.Hash)
	if len(hash) != 40 || !isValidSHA1(hash) {
		http.Error(w, "Invalid SHA1 hash", http.StatusBadRequest)
		return
	}

	prefix := hash[:5]
	suffixCount, err := checkHashInPwned(prefix, hash)

	response := CheckResponse{
		Prefix: prefix,
	}

	if err != nil {
		response.Error = err.Error()
	} else {
		response.Found = suffixCount > 0
		response.Count = suffixCount
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(response)
}

func isValidSHA1(hash string) bool {
	if len(hash) != 40 {
		return false
	}
	for _, r := range hash {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return false
		}
	}
	return true
}

// hashPassword generates SHA-1 hash of the input string
func hashPassword(pwd string) string {
	h := sha1.New()
	h.Write([]byte(pwd))
	hashBytes := h.Sum(nil)
	// Convert to hex string
	return fmt.Sprintf("%x", hashBytes)
}

// checkHashInPwned checks if the full hash (with suffix) exists in the PwnedPasswords range endpoint
func checkHashInPwned(prefix, fullHash string) (int, error) {
	// PwnedPasswords range endpoint
	url := fmt.Sprintf("https://api.pwnedpasswords.com/range/%s", prefix)

	// Make HTTP GET request
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return 0, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, fmt.Errorf("failed to make request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("HTTP %d: %s", resp.StatusCode, resp.Status)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("failed to read response: %w", err)
	}

	// Parse the response lines
	lines := strings.Split(string(body), "\n")
	var matches int

	for _, line := range lines {
		if line == "" {
			continue
		}

		// Split line into suffix and count
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}

		suffix := strings.ToLower(parts[0])
		count, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			fmt.Printf("Warning: failed to parse count to int: %s: err=%v\n", parts[1], err)
		}

		// Check if the full hash (from input) matches the suffix
		if suffix == fullHash[5:] {
			return count, nil
		}
	}

	return matches, nil
}
