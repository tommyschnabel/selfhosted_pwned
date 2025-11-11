package main

import (
	"crypto/sha1"
	"flag"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func main() {
	// Parse command-line argument
	password := flag.String("p", "", "Password to check (required)")
	flag.Parse()

	if *password == "" {
		fmt.Println("Error: Password not provided. Use --p <password>")
		return
	}

	// Step 1: Hash the password using SHA-1
	hash := hashPassword(*password)
	if hash == "" {
		fmt.Println("Error: Could not hash password")
		return
	}

	// Step 2: Extract first 5 characters of the hash (lowercase, 5 chars)
	prefix := strings.ToLower(hash)[:5]
	if len(prefix) != 5 {
		fmt.Printf("Invalid prefix: %s\n", prefix)
		return
	}

	// Step 3: Call the PwnedPasswords range endpoint
	suffixCount, err := checkHashInPwned(prefix, hash)
	if err != nil {
		fmt.Printf("Error checking hash: %v\n", err)
		return
	}

	// Step 4: Output result
	if suffixCount > 0 {
		fmt.Printf("⚠️  Password hash (prefix: %s) was found in %d breach(s)\n", prefix, suffixCount)
	} else {
		fmt.Printf("✅ Password hash (prefix: %s) not found in any known breach.\n", prefix)
	}
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
