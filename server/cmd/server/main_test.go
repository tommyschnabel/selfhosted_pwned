package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// sha1 of "password", lowercase.
const passwordHash = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"

// fakeRange stands in for api.pwnedpasswords.com/range/{prefix}. The real
// service answers with uppercase suffixes, so the fixtures do too.
func fakeRange(t *testing.T, body string, status int) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if status != http.StatusOK {
			w.WriteHeader(status)
			return
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv.URL + "/range/%s"
}

func usePwnedRange(t *testing.T, url string) {
	t.Helper()
	original := pwnedRangeURL
	pwnedRangeURL = url
	t.Cleanup(func() { pwnedRangeURL = original })
}

func TestHashPassword(t *testing.T) {
	if got := hashPassword("password"); got != passwordHash {
		t.Errorf("hashPassword = %q, want %q", got, passwordHash)
	}
	if got := hashPassword(""); len(got) != 40 {
		t.Errorf("empty password must still hash to 40 hex chars, got %q", got)
	}
}

func TestIsValidSHA1(t *testing.T) {
	cases := []struct {
		name string
		hash string
		want bool
	}{
		{"lowercase hex", passwordHash, true},
		{"too short", passwordHash[:39], false},
		{"too long", passwordHash + "a", false},
		{"uppercase is rejected", strings.ToUpper(passwordHash), false},
		{"non-hex character", strings.Repeat("z", 40), false},
		{"empty", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isValidSHA1(tc.hash); got != tc.want {
				t.Errorf("isValidSHA1(%q) = %v, want %v", tc.hash, got, tc.want)
			}
		})
	}
}

func TestCheckHashInPwned(t *testing.T) {
	suffix := strings.ToUpper(passwordHash[5:])

	t.Run("returns the breach count for a match", func(t *testing.T) {
		usePwnedRange(t, fakeRange(t, "0018A45C4D1DEF81644B54AB7F969B88D65:1\r\n"+suffix+":9659365\r\n", http.StatusOK))
		count, err := checkHashInPwned(passwordHash[:5], passwordHash)
		if err != nil {
			t.Fatalf("checkHashInPwned: %v", err)
		}
		if count != 9659365 {
			t.Errorf("count = %d, want 9659365", count)
		}
	})

	t.Run("returns zero when the suffix is absent", func(t *testing.T) {
		usePwnedRange(t, fakeRange(t, "0018A45C4D1DEF81644B54AB7F969B88D65:1\n", http.StatusOK))
		count, err := checkHashInPwned(passwordHash[:5], passwordHash)
		if err != nil {
			t.Fatalf("checkHashInPwned: %v", err)
		}
		if count != 0 {
			t.Errorf("count = %d, want 0", count)
		}
	})

	t.Run("blank and malformed lines are skipped", func(t *testing.T) {
		usePwnedRange(t, fakeRange(t, "\n\nnot-a-pair\n"+suffix+":42\n", http.StatusOK))
		count, err := checkHashInPwned(passwordHash[:5], passwordHash)
		if err != nil {
			t.Fatalf("checkHashInPwned: %v", err)
		}
		if count != 42 {
			t.Errorf("count = %d, want 42", count)
		}
	})

	t.Run("a non-200 response is an error", func(t *testing.T) {
		usePwnedRange(t, fakeRange(t, "", http.StatusTooManyRequests))
		if _, err := checkHashInPwned(passwordHash[:5], passwordHash); err == nil {
			t.Fatal("expected an error for HTTP 429")
		}
	})

	t.Run("an unreachable endpoint is an error", func(t *testing.T) {
		usePwnedRange(t, "http://127.0.0.1:1/range/%s")
		if _, err := checkHashInPwned(passwordHash[:5], passwordHash); err == nil {
			t.Fatal("expected an error when the endpoint is unreachable")
		}
	})
}

func post(t *testing.T, handler http.HandlerFunc, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/api/check/hash", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

func decode(t *testing.T, rec *httptest.ResponseRecorder) CheckResponse {
	t.Helper()
	var resp CheckResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decoding %q: %v", rec.Body.String(), err)
	}
	return resp
}

func TestHandleCheckPassword(t *testing.T) {
	suffix := strings.ToUpper(passwordHash[5:])

	t.Run("reports a breached password", func(t *testing.T) {
		usePwnedRange(t, fakeRange(t, suffix+":9659365\n", http.StatusOK))
		rec := post(t, handleCheckPassword, `{"password":"password"}`)

		if rec.Code != http.StatusOK {
			t.Fatalf("status = %d, want 200", rec.Code)
		}
		resp := decode(t, rec)
		if !resp.Found || resp.Count != 9659365 {
			t.Errorf("got %+v, want found with count 9659365", resp)
		}
		if resp.Prefix != passwordHash[:5] {
			t.Errorf("prefix = %q, want %q", resp.Prefix, passwordHash[:5])
		}
	})

	t.Run("never leaks the password or the full hash", func(t *testing.T) {
		usePwnedRange(t, fakeRange(t, suffix+":1\n", http.StatusOK))
		rec := post(t, handleCheckPassword, `{"password":"password"}`)

		body := rec.Body.String()
		if strings.Contains(body, "password\"") && strings.Contains(body, passwordHash) {
			t.Errorf("response leaks the credential: %s", body)
		}
		if strings.Contains(body, passwordHash) {
			t.Errorf("response contains the full hash, only the 5-char prefix should escape: %s", body)
		}
	})

	t.Run("reports a clean password", func(t *testing.T) {
		usePwnedRange(t, fakeRange(t, "0018A45C4D1DEF81644B54AB7F969B88D65:1\n", http.StatusOK))
		resp := decode(t, post(t, handleCheckPassword, `{"password":"password"}`))
		if resp.Found {
			t.Errorf("got %+v, want not found", resp)
		}
	})

	t.Run("upstream failures are surfaced in the error field", func(t *testing.T) {
		usePwnedRange(t, fakeRange(t, "", http.StatusServiceUnavailable))
		resp := decode(t, post(t, handleCheckPassword, `{"password":"password"}`))
		if resp.Error == "" {
			t.Error("expected an error message when the upstream fails")
		}
	})

	t.Run("rejects a missing password", func(t *testing.T) {
		rec := post(t, handleCheckPassword, `{"password":""}`)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("rejects a malformed body", func(t *testing.T) {
		rec := post(t, handleCheckPassword, `{`)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("rejects GET", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/check/password", nil)
		rec := httptest.NewRecorder()
		handleCheckPassword(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want 405", rec.Code)
		}
	})
}

func TestHandleCheckHash(t *testing.T) {
	suffix := strings.ToUpper(passwordHash[5:])

	t.Run("accepts an uppercase hash", func(t *testing.T) {
		usePwnedRange(t, fakeRange(t, suffix+":7\n", http.StatusOK))
		resp := decode(t, post(t, handleCheckHash,
			fmt.Sprintf(`{"hash":%q}`, strings.ToUpper(passwordHash))))
		if !resp.Found || resp.Count != 7 {
			t.Errorf("got %+v, want found with count 7", resp)
		}
	})

	t.Run("rejects a hash of the wrong length", func(t *testing.T) {
		rec := post(t, handleCheckHash, `{"hash":"abc"}`)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("rejects a non-hex hash", func(t *testing.T) {
		rec := post(t, handleCheckHash, fmt.Sprintf(`{"hash":%q}`, strings.Repeat("z", 40)))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("rejects a malformed body", func(t *testing.T) {
		rec := post(t, handleCheckHash, `nope`)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("status = %d, want 400", rec.Code)
		}
	})

	t.Run("rejects GET", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/check/hash", nil)
		rec := httptest.NewRecorder()
		handleCheckHash(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Errorf("status = %d, want 405", rec.Code)
		}
	})

	t.Run("responds with JSON", func(t *testing.T) {
		usePwnedRange(t, fakeRange(t, suffix+":1\n", http.StatusOK))
		rec := post(t, handleCheckHash, fmt.Sprintf(`{"hash":%q}`, passwordHash))
		if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
			t.Errorf("Content-Type = %q, want application/json", ct)
		}
	})
}
