package api

type secretJSONBytes []byte

type badSecretWriteRequest struct {
	Name  string
	Value string // want "secret-bearing API/auth field must not use string"
}

type badSecretValueResponse struct {
	Value string // want "secret-bearing API/auth field must not use string"
}

type badPKISecretResponse struct {
	Certificate string
	PrivateKey  string // want "secret-bearing API/auth field must not use string"
}

type badMachineLoginRequest struct {
	Method     string
	Credential string // want "secret-bearing API/auth field must not use string"
}

type badShareResponse struct {
	Token string // want "secret-bearing API/auth field must not use string"
}

type goodSecretWriteRequest struct {
	Name  string
	Value secretJSONBytes
}

type goodPKISecretResponse struct {
	Certificate secretJSONBytes
	PrivateKey  secretJSONBytes
}

func badConversions(req badSecretWriteRequest, keyPEM []byte, value []byte, cred struct{ Secret []byte }) {
	_ = string(keyPEM)      // want "must not convert secret bytes to string"
	_ = string(value)       // want "must not convert secret bytes to string"
	_ = string(req.Value)   // want "must not convert secret bytes to string"
	_ = string(cred.Secret) // want "must not convert secret bytes to string"
}

func allowedConversions(principalBytes []byte) {
	_ = string(principalBytes)
}
