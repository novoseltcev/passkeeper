package jwtmanager_test

import (
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/stretchr/testify/assert"

	"github.com/novoseltcev/passkeeper/pkg/jwtmanager"
	"github.com/novoseltcev/passkeeper/pkg/testutils"
)

func TestParseError_Is_True(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		got  jwt.ValidationError
		want error
	}{
		{
			name: "jwt error in inner",
			got:  jwt.ValidationError{Inner: jwt.ErrTokenMalformed},
			want: jwt.ErrTokenMalformed,
		},
		{
			name: "jwt error in errors",
			got:  jwt.ValidationError{Errors: jwt.ValidationErrorMalformed},
			want: jwt.ErrTokenMalformed,
		},
		{
			name: "jwtmanager error in inner",
			got:  jwt.ValidationError{Inner: jwtmanager.ErrTokenInvalidSubject},
			want: jwtmanager.ErrTokenInvalidSubject,
		},
		{
			name: "jwtmanager error in errors",
			got:  jwt.ValidationError{Errors: jwtmanager.ValidationErrorSubject},
			want: jwtmanager.ErrTokenInvalidSubject,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := jwtmanager.ParseError{tt.got}

			assert.ErrorIs(t, err, tt.want)
		})
	}
}

func TestParseError_Is_False(t *testing.T) {
	t.Parallel()

	err := jwtmanager.ParseError{jwt.ValidationError{Inner: testutils.Err}}

	assert.NotErrorIs(t, err, jwtmanager.ErrTokenInvalidSubject)
}
