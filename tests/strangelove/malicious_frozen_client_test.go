package strangelove

import (
	"context"
	"testing"

	clienttypes "github.com/cosmos/ibc-go/v4/modules/core/02-client/types"
	"github.com/cosmos/ibc-go/v4/modules/core/exported"
	ibctesting "github.com/cosmos/ibc-go/v4/testing"
	"github.com/strangelove-ventures/interchaintest/v4"
	"github.com/strangelove-ventures/interchaintest/v4/chain/cosmos"
	"github.com/strangelove-ventures/interchaintest/v4/chain/cosmos/wasm"
	"github.com/strangelove-ventures/interchaintest/v4/ibc"
	"github.com/strangelove-ventures/interchaintest/v4/testreporter"
	tmtypes "github.com/tendermint/tendermint/types"
	"go.uber.org/zap/zaptest"
	"withoutdoing.com/m/v2/helper"
)

// Sets up two chains, creates a connection between them with a very
// small trusting period, creates a channel between two cw-ibc-example
// contracts on that channel, causes the channel to expire.
func TestLightClientExpiry2(t *testing.T) {
	t.Parallel()
	ctx := context.Background()

	cf := interchaintest.NewBuiltinChainFactory(zaptest.NewLogger(t), []*interchaintest.ChainSpec{
		{
			Name:      "juno",
			ChainName: "juno1",
			Version:   "latest",
			ChainConfig: ibc.ChainConfig{
				GasPrices:      "0.00ujuno",
				GasAdjustment:  2.0,
				EncodingConfig: wasm.WasmEncoding(),
			},
		},
		{
			Name:      "juno",
			ChainName: "juno2",
			Version:   "latest",
			ChainConfig: ibc.ChainConfig{
				GasPrices:      "0.00ujuno",
				GasAdjustment:  2.0,
				EncodingConfig: wasm.WasmEncoding(),
			},
		},
	})

	chains, err := cf.Chains(t.Name())
	if err != nil {
		t.Fatal(err)
	}
	left, right := chains[0], chains[1]

	client, network := interchaintest.DockerSetup(t)
	relayer := interchaintest.NewBuiltinRelayerFactory(
		ibc.CosmosRly,
		zaptest.NewLogger(t),
	).Build(t, client, network)

	const ibcPath = "juno-juno"
	// trustingPeriod := time.Duration(time.Minute * 1)

	ic := interchaintest.NewInterchain().
		AddChain(left).
		AddChain(right).
		AddRelayer(relayer, "relayer")
		// AddLink(interchaintest.InterchainLink{
		// 	Chain1:  left,
		// 	Chain2:  right,
		// 	Relayer: relayer,
		// 	Path:    ibcPath,
		// 	CreateClientOpts: ibc.CreateClientOptions{
		// 		TrustingPeriod: trustingPeriod.String(),
		// 	},
		// })

	erp := testreporter.NewNopReporter().RelayerExecReporter(t)
	err = ic.Build(ctx, erp, interchaintest.InterchainBuildOptions{
		TestName:         t.Name(),
		Client:           client,
		NetworkID:        network,
		SkipPathCreation: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = ic.Close()
	})

	// err = relayer.StartRelayer(ctx, erp, ibcPath)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// t.Cleanup(func() {
	// 	err := relayer.StopRelayer(ctx, erp)
	// 	if err != nil {
	// 		t.Logf("couldn't stop relayer: %s", err)
	// 	}
	// })

	users := interchaintest.GetAndFundTestUsers(t, ctx, "default", int64(10_000_000), left, right)
	leftUser := users[0]
	// rightUser := users[1]

	leftCosmosChain := left.(*cosmos.CosmosChain)
	// rightCosmosChain := right.(*cosmos.CosmosChain)

	codeId, err := leftCosmosChain.StoreContract(ctx, leftUser.KeyName, "../wasms/cw_ibc_example.wasm")
	if err != nil {
		t.Fatal(err)
	}
	leftContract, err := leftCosmosChain.InstantiateContract(ctx, leftUser.KeyName, codeId, "{}", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(leftContract)
	// codeId, err = rightCosmosChain.StoreContract(ctx, rightUser.KeyName, "../wasms/cw_ibc_example.wasm")
	// if err != nil {
	// 	t.Fatal(err)
	// }
	// rightCosmosChain.InstantiateContract(ctx, rightUser.KeyName, codeId, "{}", true)
	// rightContract, err := rightCosmosChain.InstantiateContract(ctx, rightUser.KeyName, codeId, "{}", true)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// leftPort := "wasm." + leftContract
	// rightPort := "wasm." + rightContract

	// err = relayer.CreateChannel(ctx, erp, ibcPath, ibc.CreateChannelOptions{
	// 	SourcePortName: leftPort,
	// 	DestPortName:   rightPort,
	// 	Order:          ibc.Unordered,
	// 	Version:        "counter-1",
	// })
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// // Wait for the channel to get set up
	// err = testutil.WaitForBlocks(ctx, 10, left, right)
	// require.NoError(t, err)

	// channelInfo, err := relayer.GetChannels(ctx, erp, left.Config().ChainID)
	// if err != nil {
	// 	t.Fatal(err)
	// }

	// _leftChannel := channelInfo[1].ChannelID
	// _rightChannel := channelInfo[1].Counterparty.ChannelID
	var (
		validatorSet []*tmtypes.Validator
		signers      []tmtypes.PrivValidator
	)
	validators, err := helper.GetValidatorSet(t, ctx, leftCosmosChain)
	if err != nil {
		t.Fatal(err)
	}

	privateKeys := helper.ExtractChainPrivateKeys(t, ctx, leftCosmosChain, client)
	for i, pv := range privateKeys {
		pubKey, err := pv.GetPubKey()
		if err != nil {
			t.Fatal(err)
		}

		validator := tmtypes.NewValidator(pubKey, validators[i].VotingPower)

		validatorSet = append(validatorSet, validator)
		signers = append(signers, pv)
	}
	valSet := tmtypes.NewValidatorSet(validatorSet)

	latestHeight, err := leftCosmosChain.Height(ctx)
	trustedHeight := clienttypes.Height{
		RevisionHeight: latestHeight,
		RevisionNumber: clienttypes.ParseChainID(leftCosmosChain.Config().ChainID),
	}
	if err != nil {
		t.Fatal(err)
	}
	relayer.UpdateClients(ctx, erp, ibcPath)

	latestHeight, err = leftCosmosChain.Height(ctx)
	if err != nil {
		t.Fatal(err)
	}
	block := helper.GetBlockByHeight(t, ctx, leftCosmosChain, latestHeight)

	maliciousHeader, err := helper.CreateMaliciousTMHeader(leftCosmosChain.Config().ChainID, int64(latestHeight), trustedHeight,
		block.Header.GetTime(), valSet, valSet, signers, &block.Header)
	if err != nil {
		t.Fatal(err)
	}

	// relayerWallet, _ := relayer.GetWallet(leftCosmosChain.Config().ChainID)
	msgUpdateClient, err := clienttypes.NewMsgUpdateClient(ibctesting.FirstClientID, exported.Header(maliciousHeader), leftUser.Address)
	if err != nil {
		t.Fatal(err)
	}
	tx, err := helper.BroadcastMessages(t, ctx, leftCosmosChain, leftUser, msgUpdateClient)
	if err != nil {
		t.Fatal(err)
	}
	t.Log(tx)
}