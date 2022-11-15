/*
Copyright IBM Corp. All Rights Reserved.
SPDX-License-Identifier: Apache-2.0
*/

package builtin

import (
	// "crypto/ecdsa"
	// "crypto/elliptic"
	// "crypto/x509"
	// "encoding/hex"
	// "encoding/pem"
	"fmt"
	// "math/big"
	// "strings"

	//"github.com/youmark/pkcs8"
	//"github.com/spacemonkeygo/openssl"
	"github.com/hyperledger/fabric-protos-go/peer"
	endorsement "github.com/hyperledger/fabric/core/handlers/endorsement/api"
	identities "github.com/hyperledger/fabric/core/handlers/endorsement/api/identities"
	state "github.com/hyperledger/fabric/core/handlers/endorsement/api/state"
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

	// Handle the System chaincode case
	// if strings.Contains(string(prpBytes), "syscc") {
	signature, err := signer.Sign(append(prpBytes, identityBytes...))
	if err != nil {
		return nil, nil, errors.Wrapf(err, "could not sign the proposal response payload: %v", err)
	}
	endorsement := &peer.Endorsement{Signature: signature, Endorser: identityBytes}
	return endorsement, prpBytes, nil
	//}

	// return nil, nil, errors.Errorf("private key not retrieveable  signed Proposalbytes %s", string(sp.ProposalBytes))
	// requiredIdentityBytes := string(identityBytes)
	// AfterString := strings.Split(requiredIdentityBytes, "-----BEGIN CERTIFICATE-----")[1]
	// BeforeString := strings.Split(AfterString, "-----END CERTIFICATE-----")[0]
	// newString := "-----BEGIN CERTIFICATE-----" + BeforeString[0:] + "-----END CERTIFICATE-----"
	// pem2, _ := pem.Decode([]byte(newString))
	// cert, err2 := x509.ParseCertificate(pem2.Bytes)
	// if err2 != nil {
	// 	return nil, nil, "", errors.Errorf("Parsing Certificate Error Split bytes %s\n identity bytes %s\n Proposal Bytes %s\n signed Proposalbytes %s\n signed Signature %s\n", AfterString, string(identityBytes), string(prpBytes), string(sp.ProposalBytes), string(sp.Signature))
	// }
	// Get the priv_peer from the args

	// firstString := strings.Split(string(sp.ProposalBytes), "priv_peer")

	// If the firstString is nil, then that means the priv_peer has not passed as the args
	// so that means,we should do the normal execution of chaincode here
	// if len(firstString) == 1 {
	// 	// sign the concatenation of the proposal response and the serialized endorser identity with this endorser's key

	// 	signature, err := signer.Sign(append(prpBytes, identityBytes...))
	// 	if err != nil {
	// 		return nil, nil, errors.Wrapf(err, "could not sign the proposal response payload")
	// 	}
	// 	endorsement := &peer.Endorsement{Signature: signature, Endorser: identityBytes}
	// 	return endorsement, prpBytes, nil
	// }

	// privString1 := strings.Split(firstString[], "priv_peer")[1]
	// privString2 := strings.Split(firstString[1], "]")[0]
	// privString3 := strings.Split(privString2, ":")[1]
	// privString4 := strings.Split(privString3, ",")
	// Pub_key2 := cert.PublicKey.(*ecdsa.PublicKey)
	// fmt.Println(Pub_key2)
	// fmt.Println(privString4)
	// if len(privString4) == 1 {
	// 	privString4 := strings.Split(privString3, "-----BEGIN PRIVATE KEY-----")[1]
	// 	stringArray1 := strings.Split(privString4, "-----END PRIVATE KEY-----")
	// 	privString5 := stringArray1[0]
	// 	// sixthString := stringArray[1]
	// 	newString1 := "-----BEGIN PRIVATE KEY-----" + privString5[0:] + "-----END PRIVATE KEY-----\\n"
	// 	privateString := strings.ReplaceAll(newString1, "\\n", "\n")

	// 	newContent, _ := pem.Decode([]byte(privateString))
	// 	priv_key, err := x509.ParsePKCS8PrivateKey(newContent.Bytes)
	// 	if err != nil {
	// 		fmt.Println("private key not retrieveable ", err)
	// 	}

	// 	Pub_key1 := priv_key.(*ecdsa.PrivateKey).Public().(*ecdsa.PublicKey)

	// 	fmt.Println(Pub_key1)
	// 	verifystatus := CheckEndorsers(string(sp.ProposalBytes), Pub_key1, Pub_key2)
	// 	if verifystatus {
	// 		signature, err := signer.Sign(append(prpBytes, identityBytes...))
	// 		if err != nil {
	// 			return nil, nil, errors.Wrapf(err, "could not sign the proposal response payload: %v", err)
	// 		}
	// 		endorsement := &peer.Endorsement{Signature: signature, Endorser: identityBytes}
	// 		return endorsement, prpBytes, nil
	// 	}
	// } else {
	// 	for i := 0; i < len(privString4); i++ {
	// 		privString5 := strings.Split(privString4[i], "-----BEGIN PRIVATE KEY-----")[1]
	// 		stringArray1 := strings.Split(privString5, "-----END PRIVATE KEY-----")
	// 		privString6 := stringArray1[0]
	// 		// sixthString := stringArray[1]
	// 		newString1 := "-----BEGIN PRIVATE KEY-----" + privString6[0:] + "-----END PRIVATE KEY-----\\n"
	// 		privateString := strings.ReplaceAll(newString1, "\\n", "\n")

	// 		newContent, _ := pem.Decode([]byte(privateString))
	// 		priv_key, err := x509.ParsePKCS8PrivateKey(newContent.Bytes)
	// 		if err != nil {
	// 			fmt.Println("private key not retrieveable ", err)
	// 		}

	// 		Pub_key1 := priv_key.(*ecdsa.PrivateKey).Public().(*ecdsa.PublicKey)

	// 		fmt.Println(Pub_key1)

	// verifystatus := CheckEndorsers(string(sp.ProposalBytes), Pub_key2)
	// if verifystatus {
	// 	signature, err := signer.Sign(append(prpBytes, identityBytes...))
	// 	if err != nil {
	// 		return nil, nil, "", errors.Wrapf(err, "could not sign the proposal response payload: %v", err)
	// 	}
	// 	endorsement := &peer.Endorsement{Signature: signature, Endorser: identityBytes}
	// 	return endorsement, prpBytes, "Signature is verified", nil
	// }

	// 	}
	// }
	// return nil, nil, "Signature is not valid", errors.Errorf("could not verify the identity of the client")
	// return nil, nil, errors.Errorf("condition not mactched anywhwere Split bytes %s\n identity bytes %s\n Proposal Bytes %s\n signed Proposalbytes %s\n signed Signature %s\n", AfterString, string(identityBytes), string(prpBytes), string(sp.ProposalBytes), string(sp.Signature))
}

// Init injects dependencies into the instance of the Plugin
func (e *DefaultEndorsement) Init(dependencies ...endorsement.Dependency) error {
	isError := true
	for _, dep := range dependencies {
		sIDFetcher, isSigningIdentityFetcher := dep.(identities.SigningIdentityFetcher)
		if !isSigningIdentityFetcher {
			continue
		}
		e.SigningIdentityFetcher = sIDFetcher
		isError = false
	}

	if isError {
		return errors.New("could not find SigningIdentityFetcher in dependencies")
	}

	isError = true
	for _, dep := range dependencies {
		stateFetcher, isStateFetcher := dep.(state.StateFetcher)
		if !isStateFetcher {
			continue
		}
		e.StateFetcher = stateFetcher
		isError = false
	}

	if isError {
		return errors.New("could not find StateFetcher in dependencies")
	}

	return nil
}

// func hexToPublicKey(xHex string, yHex string) *ecdsa.PublicKey {
// 	// xBytes, _ := hex.DecodeString(xHex)
// 	x := new(big.Int)
// 	x.SetString(xHex, 16)

// 	// yBytes, _ := hex.DecodeString(yHex)
// 	// y := new(big.Int)
// 	// y.SetBytes(yBytes)
// 	y := new(big.Int)
// 	y.SetString(yHex, 16)

// 	pub := new(ecdsa.PublicKey)
// 	pub.X = x
// 	pub.Y = y

// 	pub.Curve = elliptic.P256()

// 	return pub
// }

// func CheckEndorsers(inputString string, Pub_key2 *ecdsa.PublicKey) bool {
// 	// if Pub_key1.X.Cmp(Pub_key2.X) == 0 && Pub_key1.Y.Cmp(Pub_key2.Y) == 0 {
// 	firstString := strings.Split(inputString, "sigr")[1]
// 	secondString := strings.Split(firstString, "}")[0]
// 	fourthString := strings.Split(secondString, ":")[1]

// 	fifthString := strings.Split(fourthString, "sigs")[0]
// 	sixthString := strings.ReplaceAll(fifthString, ",", "")
// 	seventhString := sixthString[0 : len(sixthString)-1]
// 	fmt.Println(seventhString)

// 	firstStringnew := strings.Split(inputString, "sigs")[1]
// 	secondStringnew := strings.Split(firstStringnew, "}")[0]
// 	// thirdString := strings.Split(secondString, "data")[1]
// 	fourthStringnew := strings.Split(secondStringnew, ":")[1]

// 	fifthStringnew := strings.Split(fourthStringnew, "pub_x")[0]
// 	sixthStringnew := strings.ReplaceAll(fifthStringnew, ",", "")
// 	seventhStringnew := sixthStringnew[0 : len(sixthStringnew)-1]
// 	fmt.Println(seventhStringnew)

// 	firstString1 := strings.Split(inputString, "msg")[1]
// 	secondString1 := strings.Split(firstString1, "}")[0]
// 	thirdString1 := strings.Split(secondString1, ":")[1]

// 	fmt.Println(string(thirdString1))

// 	firstString2 := strings.Split(inputString, "pub_x")[1]
// 	secondString2 := strings.Split(firstString2, "}")[0]
// 	fourthString2 := strings.Split(secondString2, ":")[1]
// 	fifthString2 := strings.Split(fourthString2, "pub_y")[0]
// 	sixthString2 := strings.ReplaceAll(fifthString2, ",", "")
// 	seventhString2 := sixthString2[0 : len(sixthString2)-1]
// 	fmt.Println(seventhString2)

// 	firstString3 := strings.Split(inputString, "pub_y")[1]
// 	secondString3 := strings.Split(firstString3, "}")[0]
// 	fourthString3 := strings.Split(secondString3, ":")[1]

// 	fmt.Println(fourthString3)
// 	pub_key := hexToPublicKey(seventhString2[1:len(seventhString2)-1], fourthString3[1:len(fourthString3)-1])
// 	if pub_key != nil {
// 		fmt.Println(pub_key)
// 	}

// 	r := new(big.Int)
// 	fmt.Println(1)
// 	rBytes, _ := hex.DecodeString(seventhString[1 : len(seventhString)-1])
// 	r.SetBytes(rBytes)
// 	fmt.Println("r", r)

// 	s := new(big.Int)
// 	fmt.Println(1)
// 	sBytes, _ := hex.DecodeString(seventhStringnew[1 : len(seventhStringnew)-1])
// 	s.SetBytes(sBytes)
// 	fmt.Println("s", s)
// 	fmt.Println(thirdString1[1 : len(thirdString1)-1])

// 	msgBytes, err := hex.DecodeString(thirdString1[1 : len(thirdString1)-1])
// 	if err != nil {
// 		fmt.Println(err)
// 	}

// 	fmt.Println(msgBytes)
// 	r = new(big.Int)
// 	r.SetString(seventhString[1:len(seventhString)-1], 0)
// 	s = new(big.Int)
// 	s.SetString(seventhStringnew[1:len(seventhStringnew)-1], 0)
// 	fmt.Println(r, s)

// 	isVerified := ecdsa.Verify(pub_key, msgBytes[:], r, s)

// 	// Verify

// 	return isVerified
// 	// }
// 	// return false
// }
