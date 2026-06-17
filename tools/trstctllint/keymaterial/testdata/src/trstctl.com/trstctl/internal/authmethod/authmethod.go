package authmethod

type loginRequest struct {
	Credential string // want "secret-bearing API/auth field must not use string"
}

func badCredentialParser(credential []byte) {
	_ = string(credential) // want "must not convert secret bytes to string"
}

func goodPrincipalReturn(principalBytes []byte) string {
	return string(principalBytes)
}
