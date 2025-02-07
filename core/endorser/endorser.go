/*
Copyright IBM Corp. 2016 All Rights Reserved.

SPDX-License-Identifier: Apache-2.0
*/

package endorser

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"

	//"io/ioutil"
	"crypto/ecdsa"
	"crypto/elliptic"

	//"crypto/x509"
	"encoding/hex"
	//"encoding/pem"
	"math/big"
	"strconv"
	"strings"
	"time"

	//"fmt"
	endorsement "github.com/hyperledger/fabric/core/handlers/endorsement/api/identities"

	"github.com/golang/protobuf/proto"
	"github.com/hyperledger/fabric-chaincode-go/shim"
	"github.com/hyperledger/fabric-protos-go/common"
	pb "github.com/hyperledger/fabric-protos-go/peer"
	"github.com/hyperledger/fabric-protos-go/transientstore"
	"github.com/hyperledger/fabric/common/flogging"
	"github.com/hyperledger/fabric/common/util"
	"github.com/hyperledger/fabric/core/chaincode/lifecycle"
	"github.com/hyperledger/fabric/core/common/ccprovider"

	//"github.com/hyperledger/fabric/core/config"
	"github.com/hyperledger/fabric/core/ledger"
	//"github.com/hyperledger/fabric/core/peer"

	"github.com/hyperledger/fabric/internal/pkg/identity"
	"github.com/hyperledger/fabric/msp"
	"github.com/hyperledger/fabric/protoutil"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

// type Message struct {
// 	Name  string
// 	Value string
// 	Nonce string
// }

var endorserLogger = flogging.MustGetLogger("endorser")

// The Jira issue that documents Endorser flow along with its relationship to
// the lifecycle chaincode - https://jira.hyperledger.org/browse/FAB-181

//go:generate counterfeiter -o fake/prvt_data_distributor.go --fake-name PrivateDataDistributor . PrivateDataDistributor

type PrivateDataDistributor interface {
	DistributePrivateData(channel string, txID string, privateData *transientstore.TxPvtReadWriteSetWithConfigInfo, blkHt uint64) error
}

// Support contains functions that the endorser requires to execute its tasks
type Support interface {
	identity.SignerSerializer
	// GetTxSimulator returns the transaction simulator for the specified ledger
	// a client may obtain more than one such simulator; they are made unique
	// by way of the supplied txid
	GetTxSimulator(ledgername string, txid string) (ledger.TxSimulator, error)

	// GetHistoryQueryExecutor gives handle to a history query executor for the
	// specified ledger
	GetHistoryQueryExecutor(ledgername string) (ledger.HistoryQueryExecutor, error)

	// GetTransactionByID retrieves a transaction by id
	GetTransactionByID(chid, txID string) (*pb.ProcessedTransaction, error)

	// IsSysCC returns true if the name matches a system chaincode's
	// system chaincode names are system, chain wide
	IsSysCC(name string) bool

	// Execute - execute proposal, return original response of chaincode
	Execute(txParams *ccprovider.TransactionParams, name string, input *pb.ChaincodeInput) (*pb.Response, *pb.ChaincodeEvent, error)

	// ExecuteLegacyInit - executes a deployment proposal, return original response of chaincode
	ExecuteLegacyInit(txParams *ccprovider.TransactionParams, name, version string, spec *pb.ChaincodeInput) (*pb.Response, *pb.ChaincodeEvent, error)

	// ChaincodeEndorsementInfo returns the information from lifecycle required to endorse the chaincode.
	ChaincodeEndorsementInfo(channelID, chaincodeID string, txsim ledger.QueryExecutor) (*lifecycle.ChaincodeEndorsementInfo, error)

	// CheckACL checks the ACL for the resource for the channel using the
	// SignedProposal from which an id can be extracted for testing against a policy
	CheckACL(channelID string, signedProp *pb.SignedProposal) error

	// EndorseWithPlugin endorses the response with a plugin
	EndorseWithPlugin(pluginName, channnelID string, prpBytes []byte, signedProposal *pb.SignedProposal) (*pb.Endorsement, []byte, error)

	// GetLedgerHeight returns ledger height for given channelID
	GetLedgerHeight(channelID string) (uint64, error)

	// GetDeployedCCInfoProvider returns ledger.DeployedChaincodeInfoProvider
	GetDeployedCCInfoProvider() ledger.DeployedChaincodeInfoProvider

	SigningIdentityForRequest(*pb.SignedProposal) (endorsement.SigningIdentity, error)

	NewQueryCreator(channel string) (QueryCreator, error)
}

//go:generate counterfeiter -o fake/channel_fetcher.go --fake-name ChannelFetcher . ChannelFetcher

// ChannelFetcher fetches the channel context for a given channel ID.
type ChannelFetcher interface {
	Channel(channelID string) *Channel
}

type Channel struct {
	IdentityDeserializer msp.IdentityDeserializer
}

// Endorser provides the Endorser service ProcessProposal
type Endorser struct {
	ChannelFetcher ChannelFetcher
	LocalMSP       msp.IdentityDeserializer

	PrivateDataDistributor PrivateDataDistributor
	Support                Support
	PvtRWSetAssembler      PvtRWSetAssembler
	Metrics                *Metrics
}

// call specified chaincode (system or user)
func (e *Endorser) callChaincode(txParams *ccprovider.TransactionParams, input *pb.ChaincodeInput, chaincodeName string) (*pb.Response, *pb.ChaincodeEvent, error) {
	defer func(start time.Time) {
		logger := endorserLogger.WithOptions(zap.AddCallerSkip(1))
		logger = decorateLogger(logger, txParams)
		elapsedMillisec := time.Since(start).Milliseconds()
		logger.Infof("finished chaincode: %s duration: %dms", chaincodeName, elapsedMillisec)
	}(time.Now())

	meterLabels := []string{
		"channel", txParams.ChannelID,
		"chaincode", chaincodeName,
	}

	res, ccevent, err := e.Support.Execute(txParams, chaincodeName, input)
	if err != nil {
		e.Metrics.SimulationFailure.With(meterLabels...).Add(1)
		return nil, nil, err
	}

	// per doc anything < 400 can be sent as TX.
	// fabric errors will always be >= 400 (ie, unambiguous errors )
	// "lscc" will respond with status 200 or 500 (ie, unambiguous OK or ERROR)
	if res.Status >= shim.ERRORTHRESHOLD {
		return res, nil, nil
	}

	// Unless this is the weirdo LSCC case, just return
	if chaincodeName != "lscc" || len(input.Args) < 3 || (string(input.Args[0]) != "deploy" && string(input.Args[0]) != "upgrade") {
		return res, ccevent, nil
	}

	// ----- BEGIN -  SECTION THAT MAY NEED TO BE DONE IN LSCC ------
	// if this a call to deploy a chaincode, We need a mechanism
	// to pass TxSimulator into LSCC. Till that is worked out this
	// special code does the actual deploy, upgrade here so as to collect
	// all state under one TxSimulator
	//
	// NOTE that if there's an error all simulation, including the chaincode
	// table changes in lscc will be thrown away
	cds, err := protoutil.UnmarshalChaincodeDeploymentSpec(input.Args[2])
	if err != nil {
		e.Metrics.SimulationFailure.With(meterLabels...).Add(1)
		return nil, nil, err
	}

	// this should not be a system chaincode
	if e.Support.IsSysCC(cds.ChaincodeSpec.ChaincodeId.Name) {
		e.Metrics.SimulationFailure.With(meterLabels...).Add(1)
		return nil, nil, errors.Errorf("attempting to deploy a system chaincode %s/%s", cds.ChaincodeSpec.ChaincodeId.Name, txParams.ChannelID)
	}

	if len(cds.CodePackage) != 0 {
		e.Metrics.SimulationFailure.With(meterLabels...).Add(1)
		return nil, nil, errors.Errorf("lscc upgrade/deploy should not include a code packages")
	}

	_, _, err = e.Support.ExecuteLegacyInit(txParams, cds.ChaincodeSpec.ChaincodeId.Name, cds.ChaincodeSpec.ChaincodeId.Version, cds.ChaincodeSpec.Input)
	if err != nil {
		// increment the failure to indicate instantion/upgrade failures
		meterLabels = []string{
			"channel", txParams.ChannelID,
			"chaincode", cds.ChaincodeSpec.ChaincodeId.Name,
		}
		e.Metrics.InitFailed.With(meterLabels...).Add(1)
		return nil, nil, err
	}

	return res, ccevent, err
}

// SimulateProposal simulates the proposal by calling the chaincode
func (e *Endorser) simulateProposal(txParams *ccprovider.TransactionParams, chaincodeName string, chaincodeInput *pb.ChaincodeInput) (*pb.Response, []byte, *pb.ChaincodeEvent, *pb.ChaincodeInterest, error) {
	logger := decorateLogger(endorserLogger, txParams)

	meterLabels := []string{
		"channel", txParams.ChannelID,
		"chaincode", chaincodeName,
	}

	// contents, err := ioutil.ReadFile("/home/cps16/Documents/Medical_Records/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/msp/signcerts/cert.pem")

	// if err == nil {
	// 	pem1, err2 := pem.Decode(contents)
	// 	if err2 == nil {
	// 		cert0org1, err3 := x509.ParseCertificate(pem1.Bytes)
	// 		if err3 != nil {
	// 			return &pb.Response{Status: 500, Message: err3.Error()}, nil, nil, nil, nil
	// 		} else {
	// 			return &pb.Response{Status: 500, Message: fmt.Sprintf("attr %s public key: %v", string(cert0org1.Extensions[5].Value), cert0org1.PublicKey)}, nil, nil, nil, nil
	// 		}
	// 	} else {
	// 		return &pb.Response{Status: 500, Message: fmt.Sprintf("Error 2 '%s'", err2)}, nil, nil, nil, nil
	// 	}
	// }
	// if err != nil {
	// 	return &pb.Response{Status: 500, Message: err.Error()}, nil, nil, nil, nil
	// }

	// ---3. execute the proposal and get simulation results
	res, ccevent, err := e.callChaincode(txParams, chaincodeInput, chaincodeName)
	if err != nil {
		logger.Errorf("failed to invoke chaincode %s, error: %+v", chaincodeName, err)
		return nil, nil, nil, nil, err
	}

	if txParams.TXSimulator == nil {
		return res, nil, ccevent, nil, nil
	}

	// Note, this is a little goofy, as if there is private data, Done() gets called
	// early, so this is invoked multiple times, but that is how the code worked before
	// this change, so, should be safe.  Long term, let's move the Done up to the create.
	defer txParams.TXSimulator.Done()

	simResult, err := txParams.TXSimulator.GetTxSimulationResults()
	if err != nil {
		e.Metrics.SimulationFailure.With(meterLabels...).Add(1)
		return nil, nil, nil, nil, err
	}

	if simResult.PvtSimulationResults != nil {
		if chaincodeName == "lscc" {
			// TODO: remove once we can store collection configuration outside of LSCC
			e.Metrics.SimulationFailure.With(meterLabels...).Add(1)
			return nil, nil, nil, nil, errors.New("Private data is forbidden to be used in instantiate")
		}
		pvtDataWithConfig, err := AssemblePvtRWSet(txParams.ChannelID, simResult.PvtSimulationResults, txParams.TXSimulator, e.Support.GetDeployedCCInfoProvider())
		// To read collection config need to read collection updates before
		// releasing the lock, hence txParams.TXSimulator.Done()  moved down here
		txParams.TXSimulator.Done()

		if err != nil {
			e.Metrics.SimulationFailure.With(meterLabels...).Add(1)
			return nil, nil, nil, nil, errors.WithMessage(err, "failed to obtain collections config")
		}
		endorsedAt, err := e.Support.GetLedgerHeight(txParams.ChannelID)
		if err != nil {
			e.Metrics.SimulationFailure.With(meterLabels...).Add(1)
			return nil, nil, nil, nil, errors.WithMessage(err, fmt.Sprintf("failed to obtain ledger height for channel '%s'", txParams.ChannelID))
		}
		// Add ledger height at which transaction was endorsed,
		// `endorsedAt` is obtained from the block storage and at times this could be 'endorsement Height + 1'.
		// However, since we use this height only to select the configuration (3rd parameter in distributePrivateData) and
		// manage transient store purge for orphaned private writesets (4th parameter in distributePrivateData), this works for now.
		// Ideally, ledger should add support in the simulator as a first class function `GetHeight()`.
		pvtDataWithConfig.EndorsedAt = endorsedAt
		if err := e.PrivateDataDistributor.DistributePrivateData(txParams.ChannelID, txParams.TxID, pvtDataWithConfig, endorsedAt); err != nil {
			e.Metrics.SimulationFailure.With(meterLabels...).Add(1)
			return nil, nil, nil, nil, err
		}
	}

	ccInterest, err := e.buildChaincodeInterest(simResult)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	pubSimResBytes, err := simResult.GetPubSimulationBytes()
	if err != nil {
		e.Metrics.SimulationFailure.With(meterLabels...).Add(1)
		return nil, nil, nil, nil, err
	}

	return res, pubSimResBytes, ccevent, ccInterest, nil
}

// preProcess checks the tx proposal headers, uniqueness and ACL
func (e *Endorser) preProcess(up *UnpackedProposal, channel *Channel) error {
	// at first, we check whether the message is valid

	err := up.Validate(channel.IdentityDeserializer)
	if err != nil {
		e.Metrics.ProposalValidationFailed.Add(1)
		return errors.WithMessage(err, "error validating proposal")
	}

	if up.ChannelHeader.ChannelId == "" {
		// chainless proposals do not/cannot affect ledger and cannot be submitted as transactions
		// ignore uniqueness checks; also, chainless proposals are not validated using the policies
		// of the chain since by definition there is no chain; they are validated against the local
		// MSP of the peer instead by the call to ValidateUnpackProposal above
		return nil
	}

	// labels that provide context for failure metrics
	meterLabels := []string{
		"channel", up.ChannelHeader.ChannelId,
		"chaincode", up.ChaincodeName,
	}

	// Here we handle uniqueness check and ACLs for proposals targeting a chain
	// Notice that ValidateProposalMessage has already verified that TxID is computed properly
	if _, err = e.Support.GetTransactionByID(up.ChannelHeader.ChannelId, up.ChannelHeader.TxId); err == nil {
		// increment failure due to duplicate transactions. Useful for catching replay attacks in
		// addition to benign retries
		e.Metrics.DuplicateTxsFailure.With(meterLabels...).Add(1)
		return errors.Errorf("duplicate transaction found [%s]. Creator [%x]", up.ChannelHeader.TxId, up.SignatureHeader.Creator)
	}

	// check ACL only for application chaincodes; ACLs
	// for system chaincodes are checked elsewhere
	if !e.Support.IsSysCC(up.ChaincodeName) {
		// check that the proposal complies with the Channel's writers
		if err = e.Support.CheckACL(up.ChannelHeader.ChannelId, up.SignedProposal); err != nil {
			e.Metrics.ProposalACLCheckFailed.With(meterLabels...).Add(1)
			return err
		}
	}

	return nil
}

// ProcessProposal process the Proposal
// Errors related to the proposal itself are returned with an error that results in a grpc error.
// Errors related to proposal processing (either infrastructure errors or chaincode errors) are returned with a nil error,
// clients are expected to look at the ProposalResponse response status code (e.g. 500) and message.
func (e *Endorser) ProcessProposal(ctx context.Context, signedProp *pb.SignedProposal) (*pb.ProposalResponse, error) {
	// start time for computing elapsed time metric for successfully endorsed proposals
	startTime := time.Now()
	e.Metrics.ProposalsReceived.Add(1)

	addr := util.ExtractRemoteAddress(ctx)
	// certificates := util.ExtractCertificatesFromContext(ctx)
	endorserLogger.Debug("request from", addr)

	// variables to capture proposal duration metric
	success := false

	up, err := UnpackProposal(signedProp)
	if err != nil {
		e.Metrics.ProposalValidationFailed.Add(1)
		endorserLogger.Warnw("Failed to unpack proposal", "error", err.Error())
		return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: err.Error()}}, err
	}
	found := ""
	if !e.Support.IsSysCC(up.ChaincodeName) {
		signer, err := e.Support.SigningIdentityForRequest(up.SignedProposal)
		if err != nil {
			return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: "Not able to get the signing identity"}}, err
		}
		identityBytes, err := signer.Serialize()
		if err != nil {
			return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: "Not able to get the deserialized signing identity"}}, err
		}
		requiredIdentityBytes := string(identityBytes)
		AfterString := strings.Split(requiredIdentityBytes, "-----BEGIN CERTIFICATE-----")[1]
		BeforeString := strings.Split(AfterString, "-----END CERTIFICATE-----")[0]
		newString := "-----BEGIN CERTIFICATE-----" + BeforeString[0:] + "-----END CERTIFICATE-----"
		pem2, _ := pem.Decode([]byte(newString))
		cert, err2 := x509.ParseCertificate(pem2.Bytes)
		if err2 != nil {
			// return nil, nil, "", errors.Errorf("Parsing Certificate Error Split bytes %s\n identity bytes %s\n Proposal Bytes %s\n signed Proposalbytes %s\n signed Signature %s\n", AfterString, string(identityBytes), string(prpBytes), string(sp.ProposalBytes), string(sp.Signature))
			return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: "Certificate not found"}}, err2
		}

		// Pub_key2 := cert.PublicKey.(*ecdsa.PublicKey)
		var resData map[string]map[string]string
		for _, value := range cert.Extensions {
			json.Unmarshal(value.Value, &resData)
			if resData["attrs"] != nil {
				break
			}
		}
		// message = CheckEndorsers(string(up.SignedProposal.ProposalBytes), Pub_key2)

		// Real Code
		// found, msg := DecryptMessage(string(up.SignedProposal.ProposalBytes), resData)

		// New Code
		args, found := Decrypt(up.Input.Args, resData)

		// QueryCreator, _ := e.Support.GetHistoryQueryExecutor()

		// fmt.Println(signedMessage)
		// fmt.Println(index)

		// Real Code
		// fmt.Println("Message", msg)
		// if msg != "" {
		// 	fmt.Println("Inputs before decryption")
		// 	for i := 0; i < len(up.Input.Args); i++ {
		// 		fmt.Println(string(up.Input.Args[i]))
		// 	}
		// 	fmt.Println("Inputs After decryption")
		// 	var resData Message
		// 	index := -1
		// 	for j := 0; j < len(up.Input.Args); j++ {
		// 		err := json.Unmarshal(up.Input.Args[j], &resData)
		// 		if err == nil {
		// 			resData.Value = msg
		// 			index = j
		// 			break
		// 		}
		// 	}
		// 	if index != -1 {
		// 		fmt.Println("Index", index)
		// 		up.Input.Args[index], _ = json.Marshal(&resData)
		// 		fmt.Println(string(up.Input.Args[index]))
		// 	}
		// }

		// New Code
		up.Input.Args = args

		if found == "false" {
			return &pb.ProposalResponse{Response: &pb.Response{Status: 302, Message: "Policy Not matching with this endorser"}}, nil
		}
		// if message == "Verification failed" {
		// 	return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: "Signing Verification failed for client"}}, nil
		// }
	}

	var channel *Channel
	if up.ChannelID() != "" {
		channel = e.ChannelFetcher.Channel(up.ChannelID())
		if channel == nil {
			return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: fmt.Sprintf("channel '%s' not found", up.ChannelHeader.ChannelId)}}, nil
		}
		// if up.ChannelHeader.ChannelId == "mychannel" {
		// 	Config, err := peer.GlobalConfig()
		// 	if err != nil {
		// 		return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: fmt.Sprintf("Errors '%s'", err)}}, nil
		// 	}
		// 	dockerCertPath := config.GetPath(Config.OperationsTLSCertFile)
		// 	dockerCert, err := ioutil.ReadFile(dockerCertPath)
		// 	if err != nil {
		// 		return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: fmt.Sprintf("Docker Cert Error '%s'", err)}}, nil
		// 	}
		// 	dockerKeyPath := config.GetPath(Config.OperationsTLSKeyFile)
		// 	dockerKey, err := ioutil.ReadFile(dockerKeyPath)
		// 	if err != nil {
		// 		return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: fmt.Sprintf("Docker Key Error '%s'", err)}}, nil
		// 	}

		// 	dockerCAPath := config.GetPath(Config.DockerCA)
		// 	dockerCA, err := ioutil.ReadFile(dockerCAPath)
		// 	if err != nil {
		// 		return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: fmt.Sprintf("Docker CA Error '%s'", err)}}, nil
		// 	}

		// 	return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: fmt.Sprintf("Docker Cert '%s' docker key '%s' docker ca '%s'", string(dockerCert), string(dockerKey), string(dockerCA))}}, nil
		// }
	} else {
		channel = &Channel{
			IdentityDeserializer: e.LocalMSP,
		}
	}

	// 0 -- check and validate
	err = e.preProcess(up, channel)
	if err != nil {
		endorserLogger.Warnw("Failed to preProcess proposal", "error", err.Error())
		return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: err.Error()}}, err
	}

	defer func() {
		meterLabels := []string{
			"channel", up.ChannelHeader.ChannelId,
			"chaincode", up.ChaincodeName,
			"success", strconv.FormatBool(success),
		}
		e.Metrics.ProposalDuration.With(meterLabels...).Observe(time.Since(startTime).Seconds())
	}()

	pResp, err := e.ProcessProposalSuccessfullyOrError(up, addr, found)
	if err != nil {
		endorserLogger.Warnw("Failed to invoke chaincode", "channel", up.ChannelHeader.ChannelId, "chaincode", up.ChaincodeName, "error", err.Error())
		// Return a nil error since clients are expected to look at the ProposalResponse response status code (500) and message.
		return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: err.Error()}}, nil
	}
	// certificate := util.ExtractCertificateFromContext(ctx)
	// if up.ChannelHeader.ChannelId == "mychannel" {
	// 	return &pb.ProposalResponse{Response: &pb.Response{Status: 500, Message: fmt.Sprintf("MSP ID '%s'", string(certificate.Extensions[5].Value))}}, nil
	// }

	if pResp.Endorsement != nil || up.ChannelHeader.ChannelId == "" {
		// We mark the tx as successful only if it was successfully endorsed, or
		// if it was a system chaincode on a channel-less channel and therefore
		// cannot be endorsed.
		success = true

		// total failed proposals = ProposalsReceived-SuccessfulProposals
		e.Metrics.SuccessfulProposals.Add(1)
	}
	return pResp, nil
}

func (e *Endorser) ProcessProposalSuccessfullyOrError(up *UnpackedProposal, addr string, found string) (*pb.ProposalResponse, error) {
	txParams := &ccprovider.TransactionParams{
		ChannelID:  up.ChannelHeader.ChannelId,
		TxID:       up.ChannelHeader.TxId,
		SignedProp: up.SignedProposal,
		Proposal:   up.Proposal,
	}

	if !e.Support.IsSysCC(up.ChaincodeName) {
		for i := 0; i < len(up.Input.Args); i++ {
			fmt.Println("Input Before Execution", i, string(up.Input.Args[i]))
		}
	}

	logger := decorateLogger(endorserLogger, txParams)

	// ChannelHeader   *common.ChannelHeader
	// Input           *peer.ChaincodeInput
	// Proposal        *peer.Proposal
	// SignatureHeader *common.SignatureHeader
	// SignedProposal  *peer.SignedProposal
	// ProposalHash    []byte
	// if up.ChannelHeader.ChannelId == "mychannel" {
	// 	return nil, errors.WithMessagef(nil, "Address '%s' Certificate Attr: '%s' public Key: '%v' ", address, string(cert.Extensions[5].Value), cert.PublicKey)
	// }

	if acquireTxSimulator(up.ChannelHeader.ChannelId, up.ChaincodeName) {
		txSim, err := e.Support.GetTxSimulator(up.ChannelID(), up.TxID())
		if err != nil {
			return nil, err
		}

		// txsim acquires a shared lock on the stateDB. As this would impact the block commits (i.e., commit
		// of valid write-sets to the stateDB), we must release the lock as early as possible.
		// Hence, this txsim object is closed in simulateProposal() as soon as the tx is simulated and
		// rwset is collected before gossip dissemination if required for privateData. For safety, we
		// add the following defer statement and is useful when an error occur. Note that calling
		// txsim.Done() more than once does not cause any issue. If the txsim is already
		// released, the following txsim.Done() simply returns.
		defer txSim.Done()

		hqe, err := e.Support.GetHistoryQueryExecutor(up.ChannelID())
		if err != nil {
			return nil, err
		}

		txParams.TXSimulator = txSim
		txParams.HistoryQueryExecutor = hqe
	}

	cdLedger, err := e.Support.ChaincodeEndorsementInfo(up.ChannelID(), up.ChaincodeName, txParams.TXSimulator)
	if err != nil {
		return nil, errors.WithMessagef(err, "make sure the chaincode %s has been successfully defined on channel %s and try again", up.ChaincodeName, up.ChannelID())
	}

	// 1 -- simulate
	if !e.Support.IsSysCC(up.ChaincodeName) {
		for i := 0; i < len(up.Input.Args); i++ {
			fmt.Println("Input after Execution", i, string(up.Input.Args[i]))
		}
	}

	// fmt.Println("Input2", up.Input.Args[2])

	res, simulationResult, ccevent, ccInterest, err := e.simulateProposal(txParams, up.ChaincodeName, up.Input)
	if err != nil {
		return nil, errors.WithMessage(err, "error in simulation")
	}

	cceventBytes, err := CreateCCEventBytes(ccevent)
	if err != nil {
		return nil, errors.Wrap(err, "failed to marshal chaincode event")
	}

	prpBytes, err := protoutil.GetBytesProposalResponsePayload(up.ProposalHash, res, simulationResult, cceventBytes, &pb.ChaincodeID{
		Name:    up.ChaincodeName,
		Version: cdLedger.Version,
	})
	if err != nil {
		logger.Warning("Failed marshaling the proposal response payload to bytes", err)
		return nil, errors.WithMessage(err, "failed to create the proposal response")
	}

	// if error, capture endorsement failure metric
	meterLabels := []string{
		"channel", up.ChannelID(),
		"chaincode", up.ChaincodeName,
	}

	switch {
	case res.Status >= shim.ERROR:
		return &pb.ProposalResponse{
			Response: res,
			Payload:  prpBytes,
			Interest: ccInterest,
		}, nil
	case up.ChannelID() == "":
		// Chaincode invocations without a channel ID is a broken concept
		// that should be removed in the future.  For now, return unendorsed
		// success.
		return &pb.ProposalResponse{
			Response: res,
		}, nil
	case res.Status >= shim.ERRORTHRESHOLD:
		meterLabels = append(meterLabels, "chaincodeerror", strconv.FormatBool(true))
		e.Metrics.EndorsementsFailed.With(meterLabels...).Add(1)
		logger.Debugf("chaincode error %d", res.Status)
		return &pb.ProposalResponse{
			Response: res,
		}, nil
	}

	escc := cdLedger.EndorsementPlugin

	logger.Debugf("escc for chaincode %s is %s", up.ChaincodeName, escc)

	// Note, mPrpBytes is the same as prpBytes by default endorsement plugin, but others could change it.
	endorsement, mPrpBytes, err := e.Support.EndorseWithPlugin(escc, up.ChannelID(), prpBytes, up.SignedProposal)
	if err != nil {
		meterLabels = append(meterLabels, "chaincodeerror", strconv.FormatBool(false))
		e.Metrics.EndorsementsFailed.With(meterLabels...).Add(1)
		return nil, errors.WithMessage(err, "endorsing with plugin failed")
	}

	if found != "" {
		if found == "true" {
			res.Message = "Successfully Decrypted the Message"
		}
		if found == "false" {
			res.Message = "Decryption Failed"
		}
	}
	return &pb.ProposalResponse{
		Version:     1,
		Endorsement: endorsement,
		Payload:     mPrpBytes,
		Response:    res,
		Interest:    ccInterest,
	}, nil
}

// Using the simulation results, build the ChaincodeInterest structure that the client can pass to the discovery service
// to get the correct endorsement policy for the chaincode(s) and any collections encountered.
func (e *Endorser) buildChaincodeInterest(simResult *ledger.TxSimulationResults) (*pb.ChaincodeInterest, error) {
	// build a structure that collates all the information needed for the chaincode interest:
	policies, err := parseWritesetMetadata(simResult.WritesetMetadata)
	if err != nil {
		return nil, err
	}

	// There might be public states that are read and not written.  Need to add these to the policyRequired structure.
	// This will also include private reads, because the hashed read will appear in the public RWset.
	for _, nsrws := range simResult.PubSimulationResults.GetNsRwset() {
		if e.Support.IsSysCC(nsrws.Namespace) {
			// skip system chaincodes
			continue
		}
		if _, ok := policies.policyRequired[nsrws.Namespace]; !ok {
			// There's a public RWset for this namespace, but no public or private writes, so chaincode policy is required.
			policies.add(nsrws.Namespace, "", true)
		}
	}

	for chaincode, collections := range simResult.PrivateReads {
		for collection := range collections {
			policies.add(chaincode, collection, true)
		}
	}

	ccInterest := &pb.ChaincodeInterest{}
	for chaincode, collections := range policies.policyRequired {
		if e.Support.IsSysCC(chaincode) {
			// skip system chaincodes
			continue
		}
		for collection := range collections {
			ccCall := &pb.ChaincodeCall{
				Name: chaincode,
			}
			if collection == "" { // the empty collection name here represents the public RWset
				keyPolicies := policies.sbePolicies[chaincode]
				if len(keyPolicies) > 0 {
					// For simplicity, we'll always add the SBE policies to the public ChaincodeCall, and set the disregard flag if the chaincode policy is not required.
					ccCall.KeyPolicies = keyPolicies
					if !policies.requireChaincodePolicy(chaincode) {
						ccCall.DisregardNamespacePolicy = true
					}
				} else if !policies.requireChaincodePolicy(chaincode) {
					continue
				}
			} else {
				// Since each collection in a chaincode could have different values of the NoPrivateReads flag, create a new Chaincode entry for each.
				ccCall.CollectionNames = []string{collection}
				ccCall.NoPrivateReads = !simResult.PrivateReads.Exists(chaincode, collection)
			}
			ccInterest.Chaincodes = append(ccInterest.Chaincodes, ccCall)
		}
	}

	endorserLogger.Debug("ccInterest", ccInterest)
	return ccInterest, nil
}

type metadataPolicies struct {
	// Map of SBE policies: namespace -> array of policies.
	sbePolicies map[string][]*common.SignaturePolicyEnvelope
	// Whether the chaincode/collection policy is required for endorsement: namespace -> collection -> isRequired
	// Empty collection name represents the public rwset
	// Each entry in this map represents a ChaincodeCall structure in the final ChaincodeInterest.  The boolean
	// flag isRequired is used to control whether the DisregardNamespacePolicy flag should be set.
	policyRequired map[string]map[string]bool
}

func parseWritesetMetadata(metadata ledger.WritesetMetadata) (*metadataPolicies, error) {
	mp := &metadataPolicies{
		sbePolicies:    map[string][]*common.SignaturePolicyEnvelope{},
		policyRequired: map[string]map[string]bool{},
	}
	for ns, cmap := range metadata {
		mp.policyRequired[ns] = map[string]bool{"": false}
		for coll, kmap := range cmap {
			// look through each of the states that were written to
			for _, stateMetadata := range kmap {
				if policyBytes, sbeExists := stateMetadata[pb.MetaDataKeys_VALIDATION_PARAMETER.String()]; sbeExists {
					policy, err := protoutil.UnmarshalSignaturePolicy(policyBytes)
					if err != nil {
						return nil, err
					}
					mp.sbePolicies[ns] = append(mp.sbePolicies[ns], policy)
				} else {
					// the state metadata doesn't contain data relating to SBE policy, so the chaincode/collection policy is required
					mp.policyRequired[ns][coll] = true
				}
			}
		}
	}

	return mp, nil
}

func (mp *metadataPolicies) add(ns string, coll string, required bool) {
	if entry, ok := mp.policyRequired[ns]; ok {
		entry[coll] = required
	} else {
		mp.policyRequired[ns] = map[string]bool{coll: required}
	}
}

func (mp *metadataPolicies) requireChaincodePolicy(ns string) bool {
	// if any of the states (keys) were written to without those states having a SBE policy, then the chaincode policy will be required for this namespace
	return mp.policyRequired[ns][""]
}

// determine whether or not a transaction simulator should be
// obtained for a proposal.
func acquireTxSimulator(chainID string, chaincodeName string) bool {
	if chainID == "" {
		return false
	}

	// ¯\_(ツ)_/¯ locking.
	// Don't get a simulator for the query and config system chaincode.
	// These don't need the simulator and its read lock results in deadlocks.
	switch chaincodeName {
	case "qscc", "cscc":
		return false
	default:
		return true
	}
}

// shorttxid replicates the chaincode package function to shorten txids.
// ~~TODO utilize a common shorttxid utility across packages.~~
// TODO use a formal type for transaction ID and make it a stringer
func shorttxid(txid string) string {
	if len(txid) < 8 {
		return txid
	}
	return txid[0:8]
}

func CreateCCEventBytes(ccevent *pb.ChaincodeEvent) ([]byte, error) {
	if ccevent == nil {
		return nil, nil
	}

	return proto.Marshal(ccevent)
}

func decorateLogger(logger *flogging.FabricLogger, txParams *ccprovider.TransactionParams) *flogging.FabricLogger {
	return logger.With("channel", txParams.ChannelID, "txID", shorttxid(txParams.TxID))
}

func hexToPublicKey(xHex string, yHex string) *ecdsa.PublicKey {
	// xBytes, _ := hex.DecodeString(xHex)
	x := new(big.Int)
	x.SetString(xHex, 16)

	// yBytes, _ := hex.DecodeString(yHex)
	// y := new(big.Int)
	// y.SetBytes(yBytes)
	y := new(big.Int)
	y.SetString(yHex, 16)

	pub := new(ecdsa.PublicKey)
	pub.X = x
	pub.Y = y

	pub.Curve = elliptic.P256()

	return pub
}

func CheckEndorsers(inputString string, Pub_key2 *ecdsa.PublicKey) string {
	// if Pub_key1.X.Cmp(Pub_key2.X) == 0 && Pub_key1.Y.Cmp(Pub_key2.Y) == 0 {
	message := ""
	firstString := strings.Split(inputString, "sigr")

	if len(firstString) > 0 {
		{
			secondString := strings.Split(firstString[1], "}")[0]
			fourthString := strings.Split(secondString, ":")[1]

			fifthString := strings.Split(fourthString, "sigs")[0]
			sixthString := strings.ReplaceAll(fifthString, ",", "")
			seventhString := sixthString[0 : len(sixthString)-1]
			fmt.Println(seventhString)

			firstStringnew := strings.Split(inputString, "sigs")

			if len(firstStringnew) > 1 {
				secondStringnew := strings.Split(firstStringnew[1], "}")[0]
				// thirdString := strings.Split(secondString, "data")[1]
				fourthStringnew := strings.Split(secondStringnew, ":")[1]
				fifthStringnew := strings.Split(fourthStringnew, "pub_x")[0]
				sixthStringnew := strings.ReplaceAll(fifthStringnew, ",", "")
				seventhStringnew := sixthStringnew[0 : len(sixthStringnew)-1]
				fmt.Println(seventhStringnew)

				firstString1 := strings.Split(inputString, "msg")

				if len(firstString1) > 1 {
					secondString1 := strings.Split(firstString1[1], "}")[0]
					thirdString1 := strings.Split(secondString1, ":")[1]

					fmt.Println(string(thirdString1))

					firstString2 := strings.Split(inputString, "pub_x")

					if len(firstString2) > 1 {
						secondString2 := strings.Split(firstString2[1], "}")[0]
						fourthString2 := strings.Split(secondString2, ":")[1]
						fifthString2 := strings.Split(fourthString2, "pub_y")[0]
						sixthString2 := strings.ReplaceAll(fifthString2, ",", "")
						seventhString2 := sixthString2[0 : len(sixthString2)-1]
						fmt.Println(seventhString2)

						firstString3 := strings.Split(inputString, "pub_y")

						if len(firstString3) > 1 {
							secondString3 := strings.Split(firstString3[1], "}")[0]
							fourthString3 := strings.Split(secondString3, ":")[1]

							fmt.Println(fourthString3)

							pub_key := hexToPublicKey(seventhString2[1:len(seventhString2)-1], fourthString3[1:len(fourthString3)-1])
							if pub_key != nil {
								fmt.Println(pub_key)
							}

							r := new(big.Int)
							fmt.Println(1)
							rBytes, _ := hex.DecodeString(seventhString[1 : len(seventhString)-1])
							r.SetBytes(rBytes)
							fmt.Println("r", r)

							s := new(big.Int)
							fmt.Println(1)
							sBytes, _ := hex.DecodeString(seventhStringnew[1 : len(seventhStringnew)-1])
							s.SetBytes(sBytes)
							fmt.Println("s", s)
							fmt.Println(thirdString1[1 : len(thirdString1)-1])

							msgBytes, err := hex.DecodeString(thirdString1[1 : len(thirdString1)-1])
							if err != nil {
								fmt.Println(err)
							}

							fmt.Println(msgBytes)
							r = new(big.Int)
							r.SetString(seventhString[1:len(seventhString)-1], 0)
							s = new(big.Int)
							s.SetString(seventhStringnew[1:len(seventhStringnew)-1], 0)
							fmt.Println(r, s)

							isVerified := ecdsa.Verify(pub_key, msgBytes[:], r, s)

							// Verify

							if isVerified {
								message = "Verification Passed"
							} else {
								message = "Verification failed"
							}
						}
					}

				}

			}

		}
	}
	return message
}

func DecryptMessage(inputString string, attributeMap map[string]map[string]string) (string, string) {
	state := ""
	secondArray := strings.Split(inputString, `"Name":"message","Value":`)
	if secondArray == nil {
		return state, ""
	}
	if len(secondArray) == 1 {
		return state, ""
	}
	thirdArray := strings.Split(secondArray[1], ",")
	if thirdArray == nil {
		return state, ""
	}

	fmt.Println(thirdArray[0])

	newString := strings.ReplaceAll(thirdArray[0], `"`, "")

	fmt.Println(newString)

	fourthArray := strings.Split(thirdArray[1], `"Nonce":`)
	if fourthArray == nil {
		return state, ""
	}

	if len(fourthArray) == 1 {
		return state, ""
	}

	fifthArray := strings.Split(fourthArray[1], `"}`)
	if fifthArray == nil {
		return state, ""
	}

	fmt.Println("Nonce", fifthArray[0])

	nonceString := strings.ReplaceAll(fifthArray[0], `"`, "")
	fmt.Println(nonceString)

	firstArray := strings.Split(inputString, `{"policy"`)
	secondArray1 := strings.Split(firstArray[1], "}}")
	res := `{"policy"` + secondArray1[0] + "}}"
	fmt.Println(res)
	var resData map[string]map[string]*big.Int
	err := json.Unmarshal([]byte(res), &resData)
	fmt.Println("Res Bytes", []byte(res))
	if err != nil {
		byteArray := bytes.Trim([]byte(res), `\x00`)
		json.Unmarshal(byteArray, &resData)
		fmt.Println("Bytes After Removal", byteArray)
		fmt.Println(err)
	}
	fmt.Println("Res Data", resData)

	counter := big.NewInt(0)
	actualMap := attributeMap["attrs"]
	actualResData := resData["policy"]
	fmt.Println("actualMap", actualMap)
	fmt.Println("actual Res Data", actualResData)
	for key, value := range actualResData {
		// _, present := attributeMap["attrs"][key]
		// if present {
		// 	counter.Add(value[key], counter)
		// }
		for _, value1 := range actualMap {
			if value1 == key {
				counter.Add(counter, value)
			}
		}
	}
	// if counter == big.NewInt(0) {
	// 	return state, ""
	// }

	if counter != big.NewInt(0) {
		fmt.Println("Counter", counter.String())
	}
	decodeKey, err := hex.DecodeString(counter.String())
	if err != nil {
		state = "false"
		fmt.Println("Decoding Error", err)
		return state, ""
	}
	block, err := aes.NewCipher([]byte(decodeKey))
	if err != nil {
		state = "false"
		fmt.Println("Block Error", err)
		// panic(err.Error())
		return state, ""
	}
	fmt.Println(block)
	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		// panic(err.Error())
		state = "false"
		fmt.Println("AES Error", err)
		return state, ""
	}

	fmt.Println(newString)
	bytes, _ := hex.DecodeString(newString)
	nonce, _ := hex.DecodeString(nonceString)
	fmt.Println(bytes)
	fmt.Println(nonce)
	plaintext2, err := aesgcm.Open(nil, nonce, bytes, nil)
	if err != nil {
		fmt.Println("Not able to decrypt", err.Error())
		state = "false"
		return state, ""
		// panic(err.Error())
	}
	state = "true"
	fmt.Println("Plain Text Bytes", plaintext2)
	// newPlainText :=
	fmt.Printf("Plain Text %s", plaintext2)
	return state, string(plaintext2)
}

func Decrypt(Inputs [][]byte, attributeMap map[string]map[string]string) ([][]byte, string) {
	var message1 map[string]string
	var resData map[string]map[string]*big.Int
	index := -1
	for i := 0; i < len(Inputs); i++ {
		var message2 map[string]string
		var resData2 map[string]map[string]*big.Int

		err := json.Unmarshal(Inputs[i], &message2)
		if err == nil {
			if message2["Value"] != "" {
				index = i
				fmt.Println("Index", index)
				message1 = message2
			}
		}

		err = json.Unmarshal(Inputs[i], &resData2)
		if err == nil {
			if len(resData2) != 0 {
				resData = resData2
			}
		}
	}
	fmt.Println("message", message1)
	fmt.Println("resData", resData)
	if message1["Value"] != "" {
		if resData != nil {
			counter := big.NewInt(0)
			actualMap := attributeMap["attrs"]
			actualResData := resData["policy"]
			fmt.Println("actualMap", actualMap)
			fmt.Println("Policy", actualResData)
			for key, value := range actualResData {
				// _, present := attributeMap["attrs"][key]
				// if present {
				// 	counter.Add(value[key], counter)
				// }
				for _, value1 := range actualMap {
					if value1 == key {
						counter.Add(counter, value)
					}
				}
			}
			fmt.Println("Res Data", resData)

			if counter != big.NewInt(0) {
				fmt.Println("Counter", counter.String())
			}
			decodeKey, err := hex.DecodeString(counter.String())
			if err != nil {
				// state = "false"
				fmt.Println("Decoding Error", err)
				return Inputs, "false"
			}
			block, err := aes.NewCipher([]byte(decodeKey))
			if err != nil {
				// state = "false"
				fmt.Println("Block Error", err)
				// panic(err.Error())
				return Inputs, "false"
			}
			fmt.Println(block)
			aesgcm, err := cipher.NewGCM(block)
			if err != nil {
				// panic(err.Error())
				// state = "false"
				fmt.Println("AES Error", err)
				return Inputs, "false"
			}

			value := strings.ReplaceAll(message1["Value"], `""`, "")
			nonce := strings.ReplaceAll(message1["Nonce"], `""`, "")
			fmt.Println("Value before", message1["Value"])
			fmt.Println("Nonce before", message1["Nonce"])

			fmt.Println("Value after", value)
			fmt.Println("Nonce after", nonce)

			bytes, _ := hex.DecodeString(value)
			nonceBytes, _ := hex.DecodeString(nonce)
			fmt.Println(bytes)
			fmt.Println(nonceBytes)
			plaintext2, err := aesgcm.Open(nil, nonceBytes, bytes, nil)
			if err != nil {
				fmt.Println("Not able to decrypt", err.Error())
				// state = "false"
				return Inputs, "false"
				// panic(err.Error())
			}
			// state = "true"
			fmt.Println("Plain Text Bytes", plaintext2)
			// newPlainText :=
			fmt.Printf("Plain Text %s", plaintext2)
			message1["Value"] = string(plaintext2)
			res1, _ := json.Marshal(message1)
			Inputs[index] = []byte(res1)

			return Inputs, "true"
		} else {
			return Inputs, "true"
		}
	}
	return Inputs, "true"
}
