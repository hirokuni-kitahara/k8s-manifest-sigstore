//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package x509

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pkg/errors"

	k8smnfutil "github.com/sigstore/k8s-manifest-sigstore/pkg/util"
	"github.com/sigstore/k8s-manifest-sigstore/pkg/util/kubeutil"
	log "github.com/sirupsen/logrus"
)

const (
	PEMTypePrivateKey  string = "RSA PRIVATE KEY"
	PEMTypePublicKey   string = "PUBLIC KEY"
	PEMTypeCertificate string = "CERTIFICATE"
)

var asn1EmailAddressObjectIdentifier = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 1}

// Verify certificate with CA cert, then verify signature
func VerifyBlob(msgBytes, sigBytes, certBytes []byte, caCertPathString *string) (bool, string, *int64, error) {
	caCertPath := *(caCertPathString)

	// verify certificate
	gzipCert, _ := base64.StdEncoding.DecodeString(string(certBytes))
	rawCertPem := k8smnfutil.GzipDecompress(gzipCert)
	log.Debug("verifying this certificate: ", string(rawCertPem))
	rawCertBytes := PEMDecode(rawCertPem, PEMTypeCertificate)
	cert, err := x509.ParseCertificate(rawCertBytes)
	if err != nil {
		return false, "", nil, errors.Wrap(err, "failed to load certificate")
	}

	roots := x509.NewCertPool()
	caCert, err := LoadCertificate(caCertPath)
	if err != nil {
		return false, "", nil, errors.Wrap(err, "failed to load CA certificate")
	}
	if !caCert.Equal(cert) || isSelfSignedCert(cert) {
		roots.AddCert(caCert)
	}

	opts := x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
	}
	_, err = cert.Verify(opts)
	if err != nil {
		return false, "", nil, errors.Wrap(err, "failed to verify certificate")
	}

	// verify signature
	pubKeyBytes, err := GetPublicKeyFromCertificate(rawCertPem)
	if err != nil {
		return false, "", nil, errors.Wrap(err, "failed to get public key from certificate")
	}
	gzipMsg, _ := base64.StdEncoding.DecodeString(string(msgBytes))
	rawMsg := k8smnfutil.GzipDecompress(gzipMsg)
	rawSig, _ := base64.StdEncoding.DecodeString(string(sigBytes))
	log.Debug("verifying this message: ", string(rawMsg))
	log.Debug("verifying this signature (base64): ", string(sigBytes))

	h := crypto.Hash.New(crypto.SHA256)
	_, _ = h.Write([]byte(rawMsg))
	msgHash := h.Sum(nil)
	pubKey, err := x509.ParsePKIXPublicKey(pubKeyBytes)
	if err != nil {
		return false, "", nil, errors.Wrap(err, "failed to parse public key")
	}
	err = rsa.VerifyPKCS1v15(pubKey.(*rsa.PublicKey), crypto.SHA256, msgHash, rawSig)
	if err != nil {
		return false, "", nil, errors.Wrap(err, "failed to verify signature")
	}
	signerName := GetNameInfoFromX509Cert(cert)
	log.Debugf("signature is verified successfully. signerName is %s", signerName)
	return true, signerName, nil, nil
}

// Load certificate at `certRef`
// the following patterns are supported.
// filepath --> load the cert file
// PEMbytes --> read cert PEM
// k8s secret --> load cert PEM in the k8s secret (certRef must start with `k8s://`)
// env var --> load cert PEM in the env var (certRef must start with `env://`)
func LoadCertificate(certRef string) (*x509.Certificate, error) {
	var certPemBytes []byte
	var err error

	if strings.HasPrefix(certRef, kubeutil.InClusterObjectPrefix) {
		ns, name, err := kubeutil.ParseObjectRefInCluster(certRef)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to parse secret keyRef `%s`", certRef))
		}
		secret, err := kubeutil.GetSecret(ns, name)
		if err != nil {
			return nil, errors.Wrap(err, "failed to load a kubernetes secret")
		}
		for _, val := range secret.Data {
			if val != nil {
				certPemBytes = val
			}
		}
	} else if strings.HasPrefix(certRef, k8smnfutil.EnvVarFileRefPrefix) {
		tmpCertBytes, err := k8smnfutil.LoadFileDataInEnvVar(certRef)
		if err != nil {
			return nil, errors.Wrap(err, "failed to load the key in env var")
		}
		certPemBytes = tmpCertBytes
	} else {
		if k8smnfutil.FileExists(certRef) {
			cpath := filepath.Clean(certRef)
			certPemBytes, err = os.ReadFile(cpath)
			if err != nil {
				return nil, fmt.Errorf("failed to read a cert file; %s", err.Error())
			}
		} else {
			if k8smnfutil.IsB64(certRef) {
				certRefBytes, _ := base64.StdEncoding.DecodeString(certRef)
				certRef = string(certRefBytes)
			}
			certPemBytes = []byte(certRef)
		}
	}
	if certPemBytes == nil {
		return nil, errors.New("failed to get a certificate PEM data")
	}

	certBytes := PEMDecode(certPemBytes, PEMTypeCertificate)
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}

// Load certificate chain at `certChainRef`
// the same patterns are supported as LoadCertificate()
func LoadCertificateChain(certChainRef string) ([]*x509.Certificate, error) {
	var certPemBytes []byte
	var err error

	if strings.HasPrefix(certChainRef, kubeutil.InClusterObjectPrefix) {
		ns, name, err := kubeutil.ParseObjectRefInCluster(certChainRef)
		if err != nil {
			return nil, errors.Wrap(err, fmt.Sprintf("failed to parse secret keyRef `%s`", certChainRef))
		}
		secret, err := kubeutil.GetSecret(ns, name)
		if err != nil {
			return nil, errors.Wrap(err, "failed to load a kubernetes secret")
		}
		for _, val := range secret.Data {
			if val != nil {
				certPemBytes = val
			}
		}
	} else if strings.HasPrefix(certChainRef, k8smnfutil.EnvVarFileRefPrefix) {
		tmpCertBytes, err := k8smnfutil.LoadFileDataInEnvVar(certChainRef)
		if err != nil {
			return nil, errors.Wrap(err, "failed to load the key in env var")
		}
		certPemBytes = tmpCertBytes
	} else {
		if k8smnfutil.FileExists(certChainRef) {
			cpath := filepath.Clean(certChainRef)
			certPemBytes, err = os.ReadFile(cpath)
			if err != nil {
				return nil, fmt.Errorf("failed to read a cert file; %s", err.Error())
			}
		} else {
			if k8smnfutil.IsB64(certChainRef) {
				certChainRefBytes, _ := base64.StdEncoding.DecodeString(certChainRef)
				certChainRef = string(certChainRefBytes)
			}
			certPemBytes = []byte(certChainRef)
		}
	}
	if certPemBytes == nil {
		return nil, errors.New("failed to get a certificate PEM data")
	}

	certChain := []*x509.Certificate{}
	remaining := certPemBytes
	for len(remaining) > 0 {
		var certDer *pem.Block
		certDer, remaining = pem.Decode(remaining)

		if certDer == nil {
			return nil, errors.New("error during PEM decoding")
		}

		cert, err := x509.ParseCertificate(certDer.Bytes)
		if err != nil {
			return nil, err
		}
		certChain = append(certChain, cert)
	}
	return certChain, nil
}

// Decode PEM bytes of x509 private key / public key / certificate
func PEMDecode(pemBytes []byte, mode string) []byte {
	if mode != PEMTypePrivateKey && mode != PEMTypePublicKey && mode != PEMTypeCertificate {
		return nil
	}
	p, _ := pem.Decode(pemBytes)
	if p == nil {
		return nil
	}
	return p.Bytes
}

// extract public key of certificate
func GetPublicKeyFromCertificate(certPemBytes []byte) ([]byte, error) {
	certBytes := PEMDecode(certPemBytes, PEMTypeCertificate)
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, err
	}
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return nil, err
	}
	return pubKeyBytes, nil
}

// get signer name info from cert
// try finding it in the following order
// cert.EmailAddress > cert.Subject.Names[] > cert.Subject.CommonName
func GetNameInfoFromX509Cert(cert *x509.Certificate) string {
	signerName := ""
	if len(cert.EmailAddresses) > 0 {
		signerName = cert.EmailAddresses[0]
	} else if len(cert.Subject.Names) > 0 {
		for _, pkixName := range cert.Subject.Names {
			if pkixName.Type.Equal(asn1EmailAddressObjectIdentifier) {
				signerName = pkixName.Value.(string)
				break
			}
		}
	} else {
		signerName = cert.Subject.CommonName
	}
	return signerName
}

// whether the certificate is self signed or not
func isSelfSignedCert(cert *x509.Certificate) bool {
	return bytes.Equal(cert.RawSubject, cert.RawIssuer)
}
