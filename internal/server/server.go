package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	authv1 "github.com/MatthewSerre/hyundai-bluelink-protobufs/gen/go/protos/authentication/v1"
	"github.com/golang-jwt/jwt"
	"google.golang.org/grpc"
)

var addr string = "0.0.0.0:50051"

type Server struct {
	authv1.AuthenticationServiceServer
}

type Auth struct {
	Username   string
	PIN        string
	JWTToken  string
	JWTExpiry int64
}

func main() {
	lis, err := net.Listen("tcp", addr)

	if err != nil {
		log.Fatalf("failed to listen with error: %v\n", err)
	}

	log.Printf("authentication server listening on %s\n", addr)

	s := grpc.NewServer()
	authv1.RegisterAuthenticationServiceServer(s, &Server{})

	if err = s.Serve(lis); err != nil {
		log.Fatalf("failed to server with error: %v\n", err)
	}
}

func (s *Server) Authenticate(context context.Context, request *authv1.AuthenticationRequest) (*authv1.AuthenticationResponse, error) {
	log.Println("authentication request received from client")

	auth, err := authenticate(request.Username, request.Password, request.Pin)

	if err != nil {
		log.Printf("failed to authenticate with error: %v", err)
		return &authv1.AuthenticationResponse{}, err
	}

	return &authv1.AuthenticationResponse{
		Username: auth.Username,
		Pin: auth.PIN,
		JwtToken: auth.JWTToken,
		JwtExpiry: auth.JWTExpiry,
	}, nil
}

func getCSFRToken() (string, error) {
	// Generate a new request to obtain a cross-site forgery request (CSFR) token
	req, err := http.NewRequest("GET", "https://owners.hyundaiusa.com/etc/designs/ownercommon/us/token.json", nil)

	if err != nil {
		log.Println("error generating CSRF token req:", err)
		return "", err
	}

	// Call the request
	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		log.Println("error calling CSRF token req:", err)
		return "", err
	}

	// Read the token from the response body and print it
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		log.Println("error reading CSRF token:", err)
		return "", err
	}

	var result map[string]interface{}

	json.Unmarshal([]byte(body), &result)

	csrf := result["jwt_token"].(string)

	// Generate a new request to validate the token

	req, err = http.NewRequest("GET", "https://owners.hyundaiusa.com/libs/granite/csrf/token.json", nil)

	if err != nil {
		log.Println("error generating csrf_token validation req:", err)
		return "", err
	}

	// Add the token to the request header

	req.Header.Add("csrf_token", csrf)

	// Send a request to validate the token

	resp, err = http.DefaultClient.Do(req)

	if err != nil {
		log.Println("error sending csrf validation request:", err)
		return "", err
	}

	// Validate the token

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Println("error could not validate csrf:", resp.Status)
		return "", err
	}

	return csrf, nil
}

func authenticate(username, password, pin string) (Auth, error) {
	// Obtain CSFR token

	csrf, err := getCSFRToken()

	if err != nil {
		log.Println("error obtaining CSFR token:", err)
		return Auth{}, err
	}

	// Generate a new request to obtain a JSON web token

	req, err := http.NewRequest("POST", "https://owners.hyundaiusa.com/bin/common/connectCar", nil)

	if err != nil {
		log.Println("error generating CSFR token request:", err)
		return Auth{}, err
	}

	// Add query parameters to the request

	q := req.URL.Query()
	q.Add(":cq_csrf_token", csrf)
	q.Add("url", "https://owners.hyundaiusa.com/us/en/index.html")
	q.Add("username", username)
	q.Add("password", password)
	req.URL.RawQuery = q.Encode()
	
	// Check the response status

	resp, err := http.DefaultClient.Do(req)

	if err != nil {
		log.Println("error obtaining JSON web token:", err)
		return Auth{}, err
	}

	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		log.Println("error logging in:", resp.Status)
		return Auth{}, err
	}

	// Print the response body as JSON

	body, err := io.ReadAll(resp.Body)

	if err != nil {
		log.Println("error reading authentication response:", err)
		return Auth{}, err
	}

	var loginResult map[string]any

	if err := json.Unmarshal([]byte(body), &loginResult); err != nil {
		log.Println("error reading authentication response:", err)
		return Auth{}, err
    }

	json.Unmarshal([]byte(body), &loginResult)

	var jwtID string;

	if _, ok := loginResult["RESPONSE_STRING"].(map[string]interface{})["jwt_id"].(string); ok {
		jwtID = loginResult["RESPONSE_STRING"].(map[string]interface{})["jwt_id"].(string)
	} else {
		return Auth{}, errors.New("incorrect variable type for jwtID")
	}

	// Remove the first 4 characters from jwtID if it begins with "JWT-"

	jwtIDTruncated := jwtID

	if strings.HasPrefix(jwtID, "JWT-") {
		jwtIDTruncated = jwtID[4:]
	}

	// Decode the JWT and obtain the expiration date from the "exp" field
	
	token, _ := jwt.Parse(jwtIDTruncated, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})

	expires_at := int64(token.Claims.(jwt.MapClaims)["exp"].(float64) / 1000)

	auth := Auth{ Username: username, PIN: pin, JWTToken: jwtID, JWTExpiry: expires_at }

	return auth, nil
}