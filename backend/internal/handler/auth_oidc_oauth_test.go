package handler

import (
	"testing"

	"github.com/Wei-Shaw/sub2api/internal/config"
	"github.com/Wei-Shaw/sub2api/internal/service"
)

func TestOIDCSyntheticEmail(t *testing.T) {
	tests := []struct {
		subject string
		want    string
	}{
		{"12345", "oidc-12345" + service.OIDCSyntheticEmailDomain},
		{"abc-def", "oidc-abc-def" + service.OIDCSyntheticEmailDomain},
		{"user_1", "oidc-user_1" + service.OIDCSyntheticEmailDomain},
		{"", ""},
		{"  ", ""},
	}
	for _, tt := range tests {
		got := oidcSyntheticEmail(tt.subject)
		if got != tt.want {
			t.Errorf("oidcSyntheticEmail(%q) = %q, want %q", tt.subject, got, tt.want)
		}
	}
}

func TestIsSafeOIDCSubject(t *testing.T) {
	tests := []struct {
		subject string
		want    bool
	}{
		{"12345", true},
		{"abcDEF", true},
		{"abc-def_123", true},
		{"uuid.with.dots", true},
		{"", false},
		{"   ", false},
		{"ab cd", false},
		{"ab/cd", false},
		{"ab@cd", false},
		{"abc<script>", false},
	}
	for _, tt := range tests {
		got := isSafeOIDCSubject(tt.subject)
		if got != tt.want {
			t.Errorf("isSafeOIDCSubject(%q) = %v, want %v", tt.subject, got, tt.want)
		}
	}
}

func TestOIDCParseUserInfo(t *testing.T) {
	cfg := config.OIDCConfig{}

	body := `{"sub":"user-abc-123","email":"user@example.com","preferred_username":"testuser"}`
	email, username, subject, err := oidcParseUserInfo(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if subject != "user-abc-123" {
		t.Errorf("subject = %q, want %q", subject, "user-abc-123")
	}
	if email != "user@example.com" {
		t.Errorf("email = %q, want %q", email, "user@example.com")
	}
	if username != "testuser" {
		t.Errorf("username = %q, want %q", username, "testuser")
	}
}

func TestOIDCParseUserInfoSyntheticEmail(t *testing.T) {
	cfg := config.OIDCConfig{}

	body := `{"sub":"user-abc-123","name":"TestUser"}`
	email, username, subject, err := oidcParseUserInfo(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if subject != "user-abc-123" {
		t.Errorf("subject = %q, want %q", subject, "user-abc-123")
	}
	wantEmail := "oidc-user-abc-123" + service.OIDCSyntheticEmailDomain
	if email != wantEmail {
		t.Errorf("email = %q, want %q", email, wantEmail)
	}
	if username != "TestUser" {
		t.Errorf("username = %q, want %q", username, "TestUser")
	}
}

func TestOIDCParseUserInfoCustomPaths(t *testing.T) {
	cfg := config.OIDCConfig{
		UserInfoIDPath:       "data.user_id",
		UserInfoEmailPath:    "data.mail",
		UserInfoUsernamePath: "data.login",
	}

	body := `{"data":{"user_id":"custom-id-456","mail":"custom@example.com","login":"customuser"}}`
	email, username, subject, err := oidcParseUserInfo(body, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if subject != "custom-id-456" {
		t.Errorf("subject = %q, want %q", subject, "custom-id-456")
	}
	if email != "custom@example.com" {
		t.Errorf("email = %q, want %q", email, "custom@example.com")
	}
	if username != "customuser" {
		t.Errorf("username = %q, want %q", username, "customuser")
	}
}

func TestOIDCParseUserInfoMissingID(t *testing.T) {
	cfg := config.OIDCConfig{}
	body := `{"email":"user@example.com","name":"TestUser"}`
	_, _, _, err := oidcParseUserInfo(body, cfg)
	if err == nil {
		t.Fatal("expected error for missing ID")
	}
}
