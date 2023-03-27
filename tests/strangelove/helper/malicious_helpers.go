package helper

import (
	"archive/tar"
	"context"
	"fmt"
	"io"
	"path"
	"sort"
	"strings"
	"testing"
	"time"

	clienttypes "github.com/cosmos/ibc-go/v4/modules/core/02-client/types"
	"github.com/cosmos/ibc-go/v4/modules/core/exported"
	ibctesting "github.com/cosmos/ibc-go/v4/testing"
	"github.com/tendermint/tendermint/crypto/tmhash"
	tmjson "github.com/tendermint/tendermint/libs/json"
	"github.com/tendermint/tendermint/privval"
	tmproto "github.com/tendermint/tendermint/proto/tendermint/types"
	tmprotoversion "github.com/tendermint/tendermint/proto/tendermint/version"
	tmversion "github.com/tendermint/tendermint/version"

	"github.com/cosmos/cosmos-sdk/client"
	"github.com/cosmos/cosmos-sdk/client/grpc/tmservice"
	"github.com/cosmos/cosmos-sdk/client/tx"
	"github.com/cosmos/cosmos-sdk/crypto/keys/ed25519"
	sdk "github.com/cosmos/cosmos-sdk/types"
	signingtypes "github.com/cosmos/cosmos-sdk/types/tx/signing"
	authtx "github.com/cosmos/cosmos-sdk/x/auth/tx"
	ibcmock "github.com/cosmos/ibc-go/v4/testing/mock"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/filters"
	dockerclient "github.com/docker/docker/client"
	"github.com/strangelove-ventures/interchaintest/v4/chain/cosmos"
	tmtypes "github.com/tendermint/tendermint/types"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	"github.com/cosmos/cosmos-sdk/codec"
	cryptocodec "github.com/cosmos/cosmos-sdk/crypto/codec"
	authtypes "github.com/cosmos/cosmos-sdk/x/auth/types"
	"github.com/cosmos/cosmos-sdk/x/authz"
	banktypes "github.com/cosmos/cosmos-sdk/x/bank/types"
	proposaltypes "github.com/cosmos/cosmos-sdk/x/params/types/proposal"
	upgradetypes "github.com/cosmos/cosmos-sdk/x/upgrade/types"

	feetypes "github.com/cosmos/ibc-go/v4/modules/apps/29-fee/types"
	transfertypes "github.com/cosmos/ibc-go/v4/modules/apps/transfer/types"
	connectiontypes "github.com/cosmos/ibc-go/v4/modules/core/03-connection/types"
	channeltypes "github.com/cosmos/ibc-go/v4/modules/core/04-channel/types"
	simappparams "github.com/cosmos/ibc-go/v4/testing/simapp/params"
)

func GetBlockByHeight(t *testing.T, ctx context.Context, chain *cosmos.CosmosChain, height uint64) *tmproto.Block {
	grpcConn, err := grpc.Dial(
		chain.GetHostGRPCAddress(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}

	tmService := tmservice.NewServiceClient(grpcConn)
	res, err := tmService.GetBlockByHeight(ctx, &tmservice.GetBlockByHeightRequest{
		Height: int64(height),
	})
	if err != nil {
		t.Fatal(err)
	}

	return res.Block
}

func GetValidatorSet(t *testing.T, ctx context.Context, chain *cosmos.CosmosChain) ([]*tmservice.Validator, error) {
	grpcConn, err := grpc.Dial(
		chain.GetHostGRPCAddress(),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	height, err := chain.Height(ctx)
	if err != nil {
		t.Fatal(err)
	}
	tmService := tmservice.NewServiceClient(grpcConn)
	res, err := tmService.GetValidatorSetByHeight(ctx, &tmservice.GetValidatorSetByHeightRequest{
		Height: int64(height),
	})
	if err != nil {
		return nil, err
	}

	sort.SliceStable(res.Validators, func(i, j int) bool {
		return res.Validators[i].Address < res.Validators[j].Address
	})

	return res.Validators, nil
}

func ExtractChainPrivateKeys(t *testing.T, ctx context.Context, chain *cosmos.CosmosChain, dc *dockerclient.Client) []tmtypes.PrivValidator {
	const testLabel = "ibc-test"
	testContainers, err := dc.ContainerList(ctx, types.ContainerListOptions{
		Filters: filters.NewArgs(
			// see: https://github.com/strangelove-ventures/interchaintest/blob/0bdc194c2aa11aa32479f32b19e1c50304301981/internal/dockerutil/setup.go#L31-L36
			// for the label needed to identify test containers.
			filters.Arg("label", testLabel+"="+t.Name()),
		),
	})
	if err != nil {
		t.Fatal(err)
	}

	var filePvs []privval.FilePVKey
	var pvs []tmtypes.PrivValidator
	for _, container := range testContainers {
		isNodeForDifferentChain := !strings.Contains(container.Names[0], chain.Config().ChainID)
		isFullNode := strings.Contains(container.Names[0], fmt.Sprintf("%s-fn", chain.Config().ChainID))
		if isNodeForDifferentChain || isFullNode {
			continue
		}

		validatorPrivKey := fmt.Sprintf("/var/cosmos-chain/%s/config/priv_validator_key.json", chain.Config().Name)
		readCloser, _, err := dc.CopyFromContainer(ctx, container.ID, validatorPrivKey)
		if err != nil {
			t.Fatal(err)
		}

		defer readCloser.Close()

		fileName := path.Base(validatorPrivKey)
		tr := tar.NewReader(readCloser)

		hdr, err := tr.Next()
		if err != nil {
			t.Fatal(err)
		}

		if err != nil {
			t.Fatal(err)
		}

		if hdr.Name != fileName {
			t.Fatal(fmt.Errorf("expected to find %s but found %s", fileName, hdr.Name))
		}

		privKeyFileContents, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}

		var filePV privval.FilePVKey
		err = tmjson.Unmarshal(privKeyFileContents, &filePV)
		if err != nil {
			t.Fatal(err)
		}
		filePvs = append(filePvs, filePV)
	}

	// We sort by address as GetValidatorSetByHeight also sorts by address. When iterating over them, the index
	// will correspond to the correct ibcmock.PV.
	sort.SliceStable(filePvs, func(i, j int) bool {
		return filePvs[i].Address.String() < filePvs[j].Address.String()
	})

	for _, filePV := range filePvs {
		pvs = append(pvs, &ibcmock.PV{
			PrivKey: &ed25519.PrivKey{Key: filePV.PrivKey.Bytes()},
		})
	}

	return pvs
}

const (
	invalidHashValue = "invalid_hash"
)

type Header struct {
	*tmproto.SignedHeader `protobuf:"bytes,1,opt,name=signed_header,json=signedHeader,proto3,embedded=signed_header" json:"signed_header,omitempty" yaml:"signed_header"`
	ValidatorSet          *tmproto.ValidatorSet `protobuf:"bytes,2,opt,name=validator_set,json=validatorSet,proto3" json:"validator_set,omitempty" yaml:"validator_set"`
	TrustedHeight         clienttypes.Height    `protobuf:"bytes,3,opt,name=trusted_height,json=trustedHeight,proto3" json:"trusted_height" yaml:"trusted_height"`
	TrustedValidators     *tmproto.ValidatorSet `protobuf:"bytes,4,opt,name=trusted_validators,json=trustedValidators,proto3" json:"trusted_validators,omitempty" yaml:"trusted_validators"`
}

func (h Header) ClientType() string {
	return exported.Tendermint
}

func (h Header) GetHeight() exported.Height {
	revision := clienttypes.ParseChainID(h.Header.ChainID)
	return clienttypes.NewHeight(revision, uint64(h.Header.Height))
}

// GetTime returns the current block timestamp. It returns a zero time if
// the tendermint header is nil.
// NOTE: the header.Header is checked to be non nil in ValidateBasic.
func (h Header) GetTime() time.Time {
	return h.Header.Time
}

// ValidateBasic calls the SignedHeader ValidateBasic function and checks
// that validatorsets are not nil.
// NOTE: TrustedHeight and TrustedValidators may be empty when creating client
// with MsgCreateClient
func (h Header) ValidateBasic() error {
	return nil
}

func CreateMaliciousTMHeader(
	chainID string,
	blockHeight int64,
	trustedHeight clienttypes.Height,
	timestamp time.Time,
	tmValSet, tmTrustedVals *tmtypes.ValidatorSet,
	signers []tmtypes.PrivValidator,
	oldHeader *tmproto.Header,
) (*Header, error) {

	tmHeader := tmtypes.Header{
		Version:            tmprotoversion.Consensus{Block: tmversion.BlockProtocol, App: 2},
		ChainID:            chainID,
		Height:             blockHeight,
		Time:               timestamp,
		LastBlockID:        ibctesting.MakeBlockID(make([]byte, tmhash.Size), 10_000, make([]byte, tmhash.Size)),
		LastCommitHash:     oldHeader.LastCommitHash,
		ValidatorsHash:     tmValSet.Hash(),
		NextValidatorsHash: tmValSet.Hash(),
		DataHash:           tmhash.Sum([]byte(invalidHashValue)),
		ConsensusHash:      tmhash.Sum([]byte(invalidHashValue)),
		AppHash:            tmhash.Sum([]byte(invalidHashValue)),
		LastResultsHash:    tmhash.Sum([]byte(invalidHashValue)),
		EvidenceHash:       tmhash.Sum([]byte(invalidHashValue)),
		ProposerAddress:    tmValSet.Proposer.Address, //nolint:staticcheck
	}

	hhash := tmHeader.Hash()
	blockID := ibctesting.MakeBlockID(hhash, 3, tmhash.Sum([]byte(invalidHashValue)))
	voteSet := tmtypes.NewVoteSet(chainID, blockHeight, 1, tmproto.PrecommitType, tmValSet)

	commit, err := tmtypes.MakeCommit(blockID, blockHeight, 1, voteSet, signers, timestamp)
	if err != nil {
		return nil, err
	}

	signedHeader := &tmproto.SignedHeader{
		Header: tmHeader.ToProto(),
		Commit: commit.ToProto(),
	}

	valSet, err := tmValSet.ToProto()
	if err != nil {
		return nil, err
	}

	trustedVals, err := tmTrustedVals.ToProto()
	if err != nil {
		return nil, err
	}

	return &Header{
		SignedHeader:      signedHeader,
		ValidatorSet:      valSet,
		TrustedHeight:     trustedHeight,
		TrustedValidators: trustedVals,
	}, nil
}

const (
	// DefaultGasValue is the default gas value used to configure tx.Factory
	DefaultGasValue = 500000
)

func codecAndEncodingConfig() (*codec.ProtoCodec, simappparams.EncodingConfig) {
	cfg := simappparams.MakeTestEncodingConfig()

	// ibc types
	feetypes.RegisterInterfaces(cfg.InterfaceRegistry)
	transfertypes.RegisterInterfaces(cfg.InterfaceRegistry)
	clienttypes.RegisterInterfaces(cfg.InterfaceRegistry)
	channeltypes.RegisterInterfaces(cfg.InterfaceRegistry)
	connectiontypes.RegisterInterfaces(cfg.InterfaceRegistry)

	// all other types
	upgradetypes.RegisterInterfaces(cfg.InterfaceRegistry)
	banktypes.RegisterInterfaces(cfg.InterfaceRegistry)
	authtypes.RegisterInterfaces(cfg.InterfaceRegistry)
	cryptocodec.RegisterInterfaces(cfg.InterfaceRegistry)
	proposaltypes.RegisterInterfaces(cfg.InterfaceRegistry)
	authz.RegisterInterfaces(cfg.InterfaceRegistry)

	cdc := codec.NewProtoCodec(cfg.InterfaceRegistry)
	return cdc, cfg
}

func BroadcastMessages(t *testing.T, ctx context.Context, chain *cosmos.CosmosChain, user cosmos.User, msgs ...sdk.Msg) (sdk.TxResponse, error) {
	broadcaster := cosmos.NewBroadcaster(t, chain)

	broadcaster.ConfigureClientContextOptions(func(clientContext client.Context) client.Context {
		// use a codec with all the types our tests care about registered.
		// BroadcastTx will deserialize the response and will not be able to otherwise.
		cdc, _ := codecAndEncodingConfig()

		cc := clientContext
		cc.WithCodec(cdc)
		cc.WithTxConfig(authtx.NewTxConfig(cdc, []signingtypes.SignMode{signingtypes.SignMode_SIGN_MODE_DIRECT}))
		cc.WithFromAddress(sdk.AccAddress(user.Bech32Address("cosmos")))
		cc.WithFeeGranterAddress(sdk.AccAddress(user.Bech32Address("cosmos")))
		cc.WithChainID(chain.Config().ChainID)
		cc.WithSkipConfirmation(true)
		t.Log(cc.GetFromAddress())

		return cc
	})

	broadcaster.ConfigureFactoryOptions(func(factory tx.Factory) tx.Factory {
		return factory.WithGas(DefaultGasValue).WithChainID(chain.Config().ChainID)
	})

	resp, err := cosmos.BroadcastTx(ctx, broadcaster, user, msgs...)
	if err != nil {
		return sdk.TxResponse{}, err
	}

	return resp, err
}
