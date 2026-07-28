package models

import "testing"

func TestSetPasswordAndCheckPassword(t *testing.T) {
	u := &User{}
	if err := u.SetPassword("correct-horse-battery-staple"); err != nil {
		t.Fatalf("SetPassword returned error: %v", err)
	}
	if u.PasswordHash == "" {
		t.Fatalf("expected PasswordHash to be set")
	}
	if !u.CheckPassword("correct-horse-battery-staple") {
		t.Errorf("expected CheckPassword to succeed with the correct password")
	}
	if u.CheckPassword("wrong-password") {
		t.Errorf("expected CheckPassword to fail with an incorrect password")
	}
}

func TestCheckPasswordAgainstEmptyHash(t *testing.T) {
	u := &User{}
	if u.CheckPassword("anything") {
		t.Errorf("expected CheckPassword to fail when no password has ever been set")
	}
	// A blank/empty candidate password must not match an empty hash either.
	if u.CheckPassword("") {
		t.Errorf("expected an empty candidate password not to match an unset hash")
	}
}

func TestSetPasswordChangesHash(t *testing.T) {
	u := &User{}
	_ = u.SetPassword("first-password")
	first := u.PasswordHash
	_ = u.SetPassword("second-password")
	second := u.PasswordHash
	if first == second {
		t.Errorf("expected PasswordHash to change after setting a different password")
	}
	if u.CheckPassword("first-password") {
		t.Errorf("expected the old password to no longer validate after changing it")
	}
	if !u.CheckPassword("second-password") {
		t.Errorf("expected the new password to validate")
	}
}
