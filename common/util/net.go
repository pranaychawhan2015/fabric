/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package util

import (
	"context"
	"crypto/sha256"
	"crypto/x509"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func ExtractRemoteAddress(ctx context.Context) string {
	var remoteAddress string
	p, ok := peer.FromContext(ctx)
	if !ok {
		return ""
	}
	if address := p.Addr; address != nil {
		remoteAddress = address.String()
	}
	return remoteAddress
}

func ExtractCertificateAndAddress(ctx context.Context) (string, *x509.Certificate) {
	var remoteAddress string
	p, ok := peer.FromContext(ctx)
	if !ok {
		return "", nil
	}
	if address := p.Addr; address != nil {
		remoteAddress = address.String()
	}
	authInfo := p.AuthInfo
	if authInfo == nil {
		return remoteAddress, nil
	}

	tlsInfo, isTLSConn := authInfo.(credentials.TLSInfo)
	if !isTLSConn {
		return remoteAddress, nil
	}
	certs := tlsInfo.State.PeerCertificates
	if len(certs) == 0 {
		return remoteAddress, nil
	}
	return remoteAddress, certs[0]
}

// ExtractCertificateHashFromContext extracts the hash of the certificate from the given context.
// If the certificate isn't present, nil is returned
func ExtractCertificateHashFromContext(ctx context.Context) []byte {
	rawCert := ExtractRawCertificateFromContext(ctx)
	if len(rawCert) == 0 {
		return nil
	}
	h := sha256.New()
	h.Write(rawCert)
	return h.Sum(nil)
}

// ExtractCertificateFromContext returns the TLS certificate (if applicable)
// from the given context of a gRPC stream
func ExtractCertificateFromContext(ctx context.Context) *x509.Certificate {
	pr, extracted := peer.FromContext(ctx)
	if !extracted {
		return nil
	}

	authInfo := pr.AuthInfo
	if authInfo == nil {
		return nil
	}

	tlsInfo, isTLSConn := authInfo.(credentials.TLSInfo)
	if !isTLSConn {
		return nil
	}
	certs := tlsInfo.State.PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	return certs[0]
}

func ExtractCertificatesFromContext(ctx context.Context) []byte {
	pr, extracted := peer.FromContext(ctx)
	if !extracted {
		return nil
	}

	authInfo := pr.AuthInfo
	if authInfo == nil {
		return nil
	}

	tlsInfo, isTLSConn := authInfo.(credentials.TLSInfo)
	if !isTLSConn {
		return nil
	}
	certs := tlsInfo.State.PeerCertificates
	if len(certs) == 0 {
		return nil
	}
	// NewCerts := []string{}
	// i := 0

	// for i = 0; i < len(certs); i++ {
	// 	NewCerts[i] = (string(certs[i].Raw))
	// }
	// return NewCerts

	return certs[0].Raw
}

// ExtractRawCertificateFromContext returns the raw TLS certificate (if applicable)
// from the given context of a gRPC stream
func ExtractRawCertificateFromContext(ctx context.Context) []byte {
	cert := ExtractCertificateFromContext(ctx)
	if cert == nil {
		return nil
	}
	return cert.Raw
}
