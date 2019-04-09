package mindsphere

import (
	"strings"

	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/google/uuid"
)

func toX5CFormat(pem string) (formatted string) {
	pem = strings.Replace(pem, "-----BEGIN CERTIFICATE-----", "", -1)
	pem = strings.Replace(pem, "-----END CERTIFICATE-----", "", -1)
	pem = strings.Replace(pem, "\n", "", -1)
	return pem
}

// CreateToken creates a JWT for Siemens Mindsphere, valid for 59 minutes.
func CreateToken(clientID, deviceCert, deviceKey, caCert string) (result string, err error) {
	devicePrivateKey, err := jwt.ParseRSAPrivateKeyFromPEM([]byte(deviceKey))
	if err != nil {
		return "", err
	}

	x5c := make([]string, 0, 2)

	x5c = append(x5c, toX5CFormat(deviceCert))
	x5c = append(x5c, toX5CFormat(caCert))

	jtiBytes, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	jti := jtiBytes.String()

	tenBytes, err := uuid.NewRandom()
	if err != nil {
		return "", err
	}
	ten := tenBytes.String()

	now := time.Now().Unix()

	claims := jwt.MapClaims{
		"jti":     jti,
		"iss":     clientID,
		"sub":     clientID,
		"aud":     []string{"MQTTBroker"},
		"iat":     time.Now().Unix(),
		"exp":     now + 60*59, // Expire 59 minutes
		"schemas": []string{"urn:siemens:mindsphere:v1"},
		"ten":     ten,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["x5c"] = x5c

	signedJWT, err := token.SignedString(devicePrivateKey)

	return signedJWT, nil
}
