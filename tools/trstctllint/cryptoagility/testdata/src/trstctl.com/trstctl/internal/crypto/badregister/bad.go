package badregister

func RegisterCryptoSuite(name string, implementation any) { // want `runtime crypto suite/provider registration function`
	_, _ = name, implementation
}
