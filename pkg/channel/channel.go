package channel

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/hyperledger/fabric-admin-sdk/internal/osnadmin"
	"github.com/hyperledger/fabric-admin-sdk/internal/protoutil"
	"github.com/hyperledger/fabric-admin-sdk/pkg/identity"
	"github.com/hyperledger/fabric-admin-sdk/pkg/internal/proposal"
	"github.com/hyperledger/fabric-protos-go-apiv2/peer"

	cb "github.com/hyperledger/fabric-protos-go-apiv2/common"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type ChannelList struct {
	SystemChannel interface{} `json:"systemChannel"`
	Channels      []struct {
		Name string `json:"name"`
		URL  string `json:"url"`
	} `json:"channels"`
}

// ConsensusRelation represents the relationship between the orderer and the channel's consensus cluster.
type ConsensusRelation string

const (
	// The orderer is a cluster consenter of a cluster consensus protocol (e.g. etcdraft) for a specific channel.
	// That is, the orderer is in the consenters set of the channel.
	ConsensusRelationConsenter ConsensusRelation = "consenter"
	// The orderer is following a cluster consensus protocol by pulling blocks from other orderers.
	// The orderer is NOT in the consenters set of the channel.
	ConsensusRelationFollower ConsensusRelation = "follower"
	// The orderer is NOT in the consenters set of the channel, and is just tracking (polling) the last config block
	// of the channel in order to detect when it is added to the channel.
	ConsensusRelationConfigTracker ConsensusRelation = "config-tracker"
	// The orderer runs a non-cluster consensus type, solo or kafka.
	ConsensusRelationOther ConsensusRelation = "other"
)

// Status represents the degree by which the orderer had caught up with the rest of the cluster after joining the
// channel (either as a consenter or a follower).
type Status string

const (
	// The orderer is active in the channel's consensus protocol, or following the cluster,
	// with block height > the join-block number. (Height is last block number +1).
	StatusActive Status = "active"
	// The orderer is catching up with the cluster by pulling blocks from other orderers,
	// with block height <= the join-block number.
	StatusOnBoarding Status = "onboarding"
	// The orderer is not storing any blocks for this channel.
	StatusInactive Status = "inactive"
	// The last orderer operation against the channel failed.
	StatusFailed Status = "failed"
)

// ChannelInfo carries the response to an HTTP request to List a single channel.
// This is marshaled into the body of the HTTP response.
type ChannelInfo struct {
	// The channel name.
	Name string `json:"name"`
	// The channel relative URL (no Host:Port, only path), e.g.: "/participation/v1/channels/my-channel".
	URL string `json:"url"`
	// Whether the orderer is a “consenter”, ”follower”, or "config-tracker" of
	// the cluster for this channel.
	// For non cluster consensus types (solo, kafka) it is "other".
	// Possible values:  “consenter”, ”follower”, "config-tracker", "other".
	ConsensusRelation ConsensusRelation `json:"consensusRelation"`
	// Whether the orderer is ”onboarding”, ”active”, or "inactive", for this channel.
	// For non cluster consensus types (solo, kafka) it is "active".
	// Possible values:  “onboarding”, ”active”, "inactive".
	Status Status `json:"status"`
	// Current block height.
	Height uint64 `json:"height"`
}

func CreateChannel(osnURL string, block *cb.Block, caCertPool *x509.CertPool, tlsClientCert tls.Certificate) (*http.Response, error) {
	blockBytes := protoutil.MarshalOrPanic(block)
	return osnadmin.Join(osnURL, blockBytes, caCertPool, tlsClientCert)
}

func JoinChannel(ctx context.Context, connection grpc.ClientConnInterface, id identity.SigningIdentity, block *cb.Block) error {
	blockBytes, err := proto.Marshal(block)
	if err != nil {
		return fmt.Errorf("failed to marshal block: %w", err)
	}

	prop, err := proposal.NewProposal(id, "cscc", "JoinChain", proposal.WithArguments(blockBytes), proposal.WithType(cb.HeaderType_CONFIG))
	if err != nil {
		return err
	}

	signedProp, err := proposal.NewSignedProposal(prop, id)
	if err != nil {
		return err
	}

	endorser := peer.NewEndorserClient(connection)
	proposalResp, err := endorser.ProcessProposal(ctx, signedProp)
	if err != nil {
		return err
	}

	if err := proposal.CheckSuccessfulResponse(proposalResp); err != nil {
		return err
	}

	return nil
}

func ListChannel(osnURL string, caCertPool *x509.CertPool, tlsClientCert tls.Certificate) (ChannelList, error) {

	var channels ChannelList
	resp, err := osnadmin.ListAllChannels(osnURL, caCertPool, tlsClientCert)
	if err != nil {
		return channels, err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return channels, err
	}

	if err := json.Unmarshal(body, &channels); err != nil {
		return channels, err
	}

	return channels, nil
}

// ListSingleChannel retrieves information about a specific channel from the orderer.
func ListSingleChannel(osnURL, channelID string, caCertPool *x509.CertPool, tlsClientCert tls.Certificate) (ChannelInfo, error) {
	var channelInfo ChannelInfo
	resp, err := osnadmin.ListSingleChannel(osnURL, channelID, caCertPool, tlsClientCert)
	if err != nil {
		return channelInfo, err
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return channelInfo, err
	}

	if err := json.Unmarshal(body, &channelInfo); err != nil {
		return channelInfo, err
	}

	return channelInfo, nil
}

func ListChannelOnPeer(ctx context.Context, connection grpc.ClientConnInterface, id identity.SigningIdentity) ([]*peer.ChannelInfo, error) {
	prop, err := proposal.NewProposal(id, "cscc", "GetChannels", proposal.WithType(cb.HeaderType_ENDORSER_TRANSACTION))
	if err != nil {
		return nil, err
	}

	signedProp, err := proposal.NewSignedProposal(prop, id)
	if err != nil {
		return nil, err
	}

	endorser := peer.NewEndorserClient(connection)

	proposalResp, err := endorser.ProcessProposal(ctx, signedProp)
	if err != nil {
		return nil, err
	}

	if err := proposal.CheckSuccessfulResponse(proposalResp); err != nil {
		return nil, err
	}

	var channelQueryResponse peer.ChannelQueryResponse
	err = proto.Unmarshal(proposalResp.Response.Payload, &channelQueryResponse)
	if err != nil {
		return nil, err
	}
	return channelQueryResponse.Channels, nil
}

// JoinOrderer joins an OSN to a new or existing channel.
func JoinOrderer(osnURL string, blockBytes []byte, caCertPool *x509.CertPool, tlsClientCert tls.Certificate) (ChannelInfo, error) {
	var response ChannelInfo
	chResponse, err := osnadmin.Join(osnURL, blockBytes, caCertPool, tlsClientCert)
	if err != nil {
		return response, err
	}
	if chResponse.StatusCode == 405 {
		return response, fmt.Errorf("orderer already joined the channel")
	}
	responseData, err := io.ReadAll(chResponse.Body)
	if err != nil {
		return response, err
	}
	if chResponse.StatusCode != 201 {
		return response, fmt.Errorf("error joining orderer to channel: %d", chResponse.StatusCode)
	}

	err = json.Unmarshal(responseData, &response)
	if err != nil {
		return response, err
	}

	return response, nil
}

// RemoveChannelFromOrderer removes an orderer node from a channel.
func RemoveChannelFromOrderer(osnURL, channelID string, caCertPool *x509.CertPool, tlsClientCert tls.Certificate) error {
	response, err := osnadmin.Remove(osnURL, channelID, caCertPool, tlsClientCert)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("error removing orderer from channel: %d", response.StatusCode)
	}
	return nil
}
