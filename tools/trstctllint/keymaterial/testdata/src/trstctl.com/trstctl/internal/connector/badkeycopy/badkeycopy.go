// SPDX-License-Identifier: MPL-2.0

package badkeycopy

import "encoding/base64"

type Deployment struct {
	KeyPEM []byte
}

func badDeploymentKeyCopies(dep Deployment) {
	_ = string(dep.KeyPEM)                            // want "must not convert Deployment.KeyPEM"
	_ = base64.StdEncoding.EncodeToString(dep.KeyPEM) // want "must not convert Deployment.KeyPEM"
}

func allowedCertificateText(certPEM []byte) {
	_ = string(certPEM)
}
