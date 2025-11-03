package services

import (
    "time"

    "github.com/golang-jwt/jwt/v5"

    "vpnpannel/internal/config"
)

type UserClaims struct {
    UserID   uint   `json:"uid"`
    Role     string `json:"role"`
    DeviceID string `json:"did,omitempty"`
    jwt.RegisteredClaims
}

func GenerateUserToken(userID uint, role string, deviceID string, ttl time.Duration) (string, error) {
    claims := UserClaims{
        UserID:   userID,
        Role:     role,
        DeviceID: deviceID,
        RegisteredClaims: jwt.RegisteredClaims{
            ExpiresAt: jwt.NewNumericDate(time.Now().Add(ttl)),
            IssuedAt:  jwt.NewNumericDate(time.Now()),
        },
    }
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
    return token.SignedString([]byte(config.Current.JWTSecret))
}

func ParseToken(tokenString string) (*UserClaims, error) {
    token, err := jwt.ParseWithClaims(tokenString, &UserClaims{}, func(t *jwt.Token) (interface{}, error) {
        return []byte(config.Current.JWTSecret), nil
    })
    if err != nil {
        return nil, err
    }
    if claims, ok := token.Claims.(*UserClaims); ok && token.Valid {
        return claims, nil
    }
    return nil, jwt.ErrTokenInvalidClaims
}


