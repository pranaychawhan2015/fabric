/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package main

import (
	"crypto/x509"
	//"encoding/pem"
	"errors"
	"fmt"
	"strings"

	//"io/ioutil"

	"github.com/hyperledger/fabric-protos-go/peer"
	endorsement "github.com/hyperledger/fabric/core/handlers/endorsement/api"
	identities "github.com/hyperledger/fabric/core/handlers/endorsement/api/identities"
)

// To build the plugin,
// run:
//    go build -buildmode=plugin -o escc.so plugin.go

// DefaultEndorsementFactory returns an endorsement plugin factory which returns plugins
// that behave as the default endorsement system chaincode
type DefaultEndorsementFactory struct{}

// New returns an endorsement plugin that behaves as the default endorsement system chaincode
func (*DefaultEndorsementFactory) New() endorsement.Plugin {
	return &DefaultEndorsement{}
}

// DefaultEndorsement is an endorsement plugin that behaves as the default endorsement system chaincode
type DefaultEndorsement struct {
	identities.SigningIdentityFetcher
}

// Endorse signs the given payload(ProposalResponsePayload bytes), and optionally mutates it.
// Returns:
// The Endorsement: A signature over the payload, and an identity that is used to verify the signature
// The payload that was given as input (could be modified within this function)
// Or error on failure
func (e *DefaultEndorsement) Endorse(prpBytes []byte, sp *peer.SignedProposal) (*peer.Endorsement, []byte, error) {
	signer, err := e.SigningIdentityForRequest(sp)
	if err != nil {
		return nil, nil, fmt.Errorf("failed fetching signing identity: %v", err)
	}
	// serialize the signing identity
	identityBytes, err := signer.Serialize()
	if err != nil {
		return nil, nil, fmt.Errorf("could not serialize the signing identity: %v", err)
	}
	fmt.Println("System Chaincode New one which has established")

	// contents, err := ioutil.ReadFile("/home/cps16/Documents/Medical_Records/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/msp/signcerts/cert.pem")
	// if err != nil {
	// 	fmt.Println("could not find the file at the respective path")
	// 	return nil, nil, fmt.Errorf("could not find the file at the respective path")
	// }
	// decodedData, _ := pem.Decode(identityBytes)
	// if decodedData == nil {
	// 	fmt.Println("could not decode the file")
	// 	return nil, nil, fmt.Errorf("could not decode the file ")
	// }
	certificate, err2 := x509.ParseCertificate(identityBytes)
	fmt.Printf("Split bytes %q\n Proposal Bytes %q\n Identity Bytes %q\n", strings.Split(string(identityBytes), "\b"), string(prpBytes), string(identityBytes))

	if err2 != nil {
		fmt.Println("could not find the Certificate")
	}
	if certificate.Issuer.Organization[0] == "org1.example.com" {
		// sign the concatenation of the proposal response and the serialized endorser identity with this endorser's key
		fmt.Println("condition matched")

		signature, err := signer.Sign(append(prpBytes, identityBytes...))
		if err != nil {
			return nil, nil, fmt.Errorf("could not sign the proposal response payload: %v", err)
		}
		// return nil, nil, fmt.Errorf("Signature %s Endorser %s", string(signature), string(identityBytes))
		endorsement := &peer.Endorsement{Signature: signature, Endorser: identityBytes}
		return endorsement, prpBytes, nil
	} else {
		fmt.Println("condition not matched")
	}
	return nil, nil, fmt.Errorf("condition not matched anywhere")
}

// Init injects dependencies into the instance of the Plugin
func (e *DefaultEndorsement) Init(dependencies ...endorsement.Dependency) error {
	for _, dep := range dependencies {
		sIDFetcher, isSigningIdentityFetcher := dep.(identities.SigningIdentityFetcher)
		if !isSigningIdentityFetcher {
			continue
		}
		e.SigningIdentityFetcher = sIDFetcher
		return nil
	}
	return errors.New("could not find SigningIdentityFetcher in dependencies")
}

// NewPluginFactory is the function ran by the plugin infrastructure to create an endorsement plugin factory.
func NewPluginFactory() endorsement.PluginFactory {
	return &DefaultEndorsementFactory{}
}
