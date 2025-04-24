package main

import (
	"encoding/hex"
	"fmt"
	"time"

	"github.com/kaspanet/kaspad/cmd/kaspawallet/keys"
	"github.com/kaspanet/kaspad/cmd/kaspawallet/libkaspawallet"
	"github.com/kaspanet/kaspad/cmd/kaspawallet/utils"
	"github.com/kaspanet/kaspad/domain/consensus/model/externalapi"
	"github.com/kaspanet/kaspad/domain/consensus/utils/constants"
	"github.com/kaspanet/kaspad/domain/dagconfig"
	"github.com/kaspanet/kaspad/infrastructure/network/rpcclient"
	"github.com/kaspanet/kaspad/util/txmass"
)

const (
	keysPath                            = "/Users/sergi/Library/Application Support/Kaspawallet/kaspa-testnet-10/keys.json"
	minChangeTarget                     = constants.SompiPerKaspa * 10
	minFeeRate                          = 1.0
	address                             = "kaspatest:qp96y8xa6gqlh3a5c6wu9x73a5egvsw2vk7w7nzm8x98wvkavjlg29zvta4m6"
	numIndexesToQueryForFarAddresses    = 100
	numIndexesToQueryForRecentAddresses = 1000
)

type walletAddressSet map[string]*walletAddress

func (was walletAddressSet) strings() []string {
	addresses := make([]string, 0, len(was))
	for addr := range was {
		addresses = append(addresses, addr)
	}
	return addresses
}

type Client struct {
	rpcClient                       *rpcclient.RPCClient // RPC client for ongoing user requests
	params                          *dagconfig.Params
	coinbaseMaturity                uint64 // Is different from default if we use testnet-11
	usedOutpoints                   map[externalapi.DomainOutpoint]time.Time
	startTimeOfLastCompletedRefresh time.Time

	utxosSortedByAmount  []*walletUTXO
	keysFile             *keys.File
	txMassCalculator     *txmass.Calculator
	mempoolExcludedUTXOs map[externalapi.DomainOutpoint]*walletUTXO
	addressSet           walletAddressSet
	nextSyncStartIndex   uint32
}

func (c *Client) Send(address string, amount string) error {

	sendAmountSompi, err := utils.KasToSompi(amount)
	if err != nil {
		return err
	}

	err = c.collectFarAddresses()
	if err != nil {
		return err
	}

	/*err = c.collectRecentAddresses()
	if err != nil {
		return err
	}*/

	c.refreshUTXOs()

	unsignedTransactions, err := c.createUnsignedTransactions(address, sendAmountSompi, false,
		[]string{}, false, nil)
	if err != nil {
		return err
	}

	mnemonics := []string{"seed sun dice artwork mango length sudden trial shove wolf dove during aerobic embark copy border unveil convince cost civil there wrong echo front"}

	signedTransactions := make([][]byte, len(unsignedTransactions))
	for i, unsignedTransaction := range unsignedTransactions {
		fmt.Println(hex.EncodeToString(unsignedTransaction))

		signedTransaction, err := libkaspawallet.Sign(c.params, mnemonics, unsignedTransaction, false)
		if err != nil {
			return err
		}
		fmt.Println(hex.EncodeToString(signedTransaction))

		signedTransactions[i] = signedTransaction
	}

	fmt.Printf("Broadcasting %d transaction(s)\n", len(signedTransactions))

	const chunkSize = 100 // To avoid sending a message bigger than the gRPC max message size, we split it to chunks
	for offset := 0; offset < len(signedTransactions); offset += chunkSize {
		end := len(signedTransactions)
		if offset+chunkSize <= len(signedTransactions) {
			end = offset + chunkSize
		}

		chunk := signedTransactions[offset:end]
		fmt.Println(hex.EncodeToString(chunk[0]))
		txIDs, err := c.broadcast(chunk, false)
		if err != nil {
			return err
		}
		/*response, err := daemonClient.Broadcast(broadcastCtx, &pb.BroadcastRequest{Transactions: chunk})
		if err != nil {
			return err
		}*/
		fmt.Printf("Broadcasted %d transaction(s) (broadcasted %.2f%% of the transactions so far)\n", len(chunk), 100*float64(end)/float64(len(signedTransactions)))
		fmt.Println("Broadcasted Transaction ID(s): ")
		for _, txID := range txIDs {
			fmt.Printf("\t%s\n", txID)
		}
	}

	for _, signedTx := range signedTransactions {
		fmt.Printf("\t%x\n\n", signedTx)
	}
	return nil

}
