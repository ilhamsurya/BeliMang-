package validator

import (
	"regexp"
	"unicode"
)

const (
	minUsernameLen = 5
	maxUsernameLen = 30
	minPasswordLen = 5
	maxPasswordLen = 30
)

func IsValidEmail(email string) bool {
	emailRegex := regexp.MustCompile(`^[a-zA-Z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,4}$`)
	return emailRegex.MatchString(email)
}

func IsValidUsername(username string) bool {
	return len(username) >= minUsernameLen && len(username) <= maxUsernameLen
}

func IsSolidPassword(s string) bool {
	var (
		hasMinMaxLen = false
		hasNumber    = false
		hasLetter    = false
	)

	if len(s) >= minPasswordLen && len(s) <= maxPasswordLen {
		hasMinMaxLen = true
	}

	for _, char := range s {
		switch {
		case unicode.IsLetter(char):
			hasLetter = true
		case unicode.IsNumber(char):
			hasNumber = true
		}
	}

	return hasMinMaxLen && (hasLetter || hasNumber)
}
