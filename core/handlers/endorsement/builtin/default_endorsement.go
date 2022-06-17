/*
Copyright IBM Corp. All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package builtin

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	//"os"
	"strings"

	//"io/ioutil"
	"github.com/hyperledger/fabric-protos-go/peer"
	endorsement "github.com/hyperledger/fabric/core/handlers/endorsement/api"
	identities "github.com/hyperledger/fabric/core/handlers/endorsement/api/identities"
	state "github.com/hyperledger/fabric/core/handlers/endorsement/api/state"
	// p "github.com/hyperledger/fabric/msp"
	"github.com/pkg/errors"
)

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
	state.StateFetcher
}

// Endorse signs the given payload(ProposalResponsePayload bytes), and optionally mutates it.
// Returns:
// The Endorsement: A signature over the payload, and an identity that is used to verify the signature
// The payload that was given as input (could be modified within this function)
// Or error on failure
func (e *DefaultEndorsement) Endorse(prpBytes []byte, sp *peer.SignedProposal) (*peer.Endorsement, []byte, error) {
	signer, err := e.SigningIdentityForRequest(sp)
	if err != nil {
		return nil, nil, errors.Wrapf(err, "failed fetching signing identity")
	}
	// serialize the signing identity
	identityBytes, err := signer.Serialize()
	if err != nil {
		fmt.Println("could not serialize the signing identity")
		return nil, nil, errors.Wrapf(err, "could not serialize the signing identity")
	}

	state, err := e.FetchState()
	if err != nil {
		return nil, nil, errors.Wrapf(err, "could not get the state")
	}

	// if signer.identity.msp != nil {
	// 	keyinfo := &msp.KeyInfo{KeyIdentifier: "PEER", KeyMaterial: nil}
	// 	sigid := &msp.SigningIdentityInfo{PublicSigner: identityBytes, PrivateSigner: keyinfo}
	// 	_, _, pvkey := signer.identity.msp.getSigningIdentityFromConf(sigid)
	// 	return nil, nil, errors.Wrapf(err, "signer identity msp private key :", pvkey)
	// }

	// content, err1 := os.ReadFile("/home/cps16/Documents/Medical_Records/test-network/organizations/peerOrganizations/org3.example.com/peers/peer2.org3.example.com/msp/keystore/priv_sk")
	// if err1 != nil {
	// 	return nil, nil, errors.Errorf("Could not find the private key %s", err1)
	// }
	// if content != nil {
	// 	return nil, nil, errors.Errorf("Successful Private key decryption %s", string(content))
	// }

	// Handle the System chaincode case
	if strings.Contains(string(prpBytes), "syscc") {
		signature, err := signer.Sign(append(prpBytes, identityBytes...))
		if err != nil {
			return nil, nil, errors.Wrapf(err, "could not sign the proposal response payload: %v", err)
		}
		endorsement := &peer.Endorsement{Signature: signature, Endorser: identityBytes}
		return endorsement, prpBytes, nil
	}
	requiredIdentityBytes := string(identityBytes)

	// requiredIndex := strings.Index(requiredIdentityBytes, "-")
	AfterString := strings.Split(requiredIdentityBytes, "-----BEGIN CERTIFICATE-----")[1]
	BeforeString := strings.Split(AfterString, "-----END CERTIFICATE-----")[0]
	// pem2, _ := pem.Decode([]byte(strings.Split(string(identityBytes), "-----")[1]))
	newString := "-----BEGIN CERTIFICATE-----" + BeforeString[0:] + "-----END CERTIFICATE-----"
	pem2, _ := pem.Decode([]byte(newString))
	certificate, err2 := x509.ParseCertificate(pem2.Bytes)
	fmt.Printf("Split bytes %q\n identity bytes %q\n Proposal Bytes %q\n", strings.Split(string(identityBytes), "\b"), string(identityBytes), string(prpBytes))

	if err2 != nil {
		fmt.Println("could not find the Certificate")
		return nil, nil, errors.Errorf("could not find the Certificate Split bytes %q\n identity bytes %q\n Proposal Bytes %q\n certificate Public Key: %s\n ", strings.Split(string(identityBytes), "\b"), string(identityBytes), string(prpBytes), certificate.PublicKey)
	}
	if certificate.Issuer.Organization[0] == "org1.example.com" {
		// sign the concatenation of the proposal response and the serialized endorser identity with this endorser's key
		fmt.Println("condition matched")
		signature, err := signer.Sign(append(prpBytes, identityBytes...))
		if err != nil {
			return nil, nil, errors.Wrapf(err, "could not sign the proposal response payload: %v", err)
		}
		endorsement := &peer.Endorsement{Signature: signature, Endorser: identityBytes}
		return endorsement, prpBytes, nil
	} else {
		fmt.Println("condition not matchde")
	}

	if certificate != nil {
		return nil, nil, errors.Errorf("condition not mactched anywhwere Split bytes %q\n identity bytes %q\n Proposal Bytes %q\n Certificate Organization %s\n ", AfterString, string(identityBytes), string(prpBytes), certificate.Issuer.Organization[0])
	}

	return nil, nil, errors.Errorf("condition not mactched anywhwere Split bytes %q\n identity bytes %q\n Proposal Bytes %q\n", AfterString, string(identityBytes), string(prpBytes))
	// sign the concatenation of the proposal response and the serialized endorser identity with this endorser's key
	// signature, err := signer.Sign(append(prpBytes, identityBytes...))
	// if err != nil {
	// 	return nil, nil, errors.Wrapf(err, "could not sign the proposal response payload")
	// }
	// endorsement := &peer.Endorsement{Signature: signature, Endorser: identityBytes}
	// return endorsement, prpBytes, nil
}

// Init injects dependencies into the instance of the Plugin
func (e *DefaultEndorsement) Init(dependencies ...endorsement.Dependency) error {
	for _, dep := range dependencies {
		sIDFetcher, isSigningIdentityFetcher := dep.(identities.SigningIdentityFetcher)
		if !isSigningIdentityFetcher {
			continue
		}
		e.SigningIdentityFetcher = sIDFetcher
		stateFetcher, isStateFetcher := dep.(state.StateFetcher)
		if !isStateFetcher {
			continue
		}
		e.StateFetcher = stateFetcher
		return nil
	}
	return errors.New("could not find SigningIdentityFetcher in dependencies")
}
