package main

import (

	// Replace with actual path

	"fmt"
	"log"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/kaspanet/kaspad/util/txmass"

	"github.com/kaspanet/kaspad/app/appmessage"
	"github.com/kaspanet/kaspad/cmd/kaspawallet/daemon/server"
	"github.com/kaspanet/kaspad/cmd/kaspawallet/keys"
	"github.com/kaspanet/kaspad/cmd/kaspawallet/libkaspawallet"
	"github.com/kaspanet/kaspad/cmd/kaspawallet/libkaspawallet/bip32"
	"github.com/kaspanet/kaspad/cmd/kaspawallet/libkaspawallet/serialization"
	"github.com/kaspanet/kaspad/domain/consensus/model/externalapi"
	"github.com/kaspanet/kaspad/domain/consensus/utils/constants"
	"github.com/kaspanet/kaspad/domain/dagconfig"
	"github.com/kaspanet/kaspad/infrastructure/network/rpcclient"
	"github.com/kaspanet/kaspad/util"
)

const (
	keysPath        = "/Users/sergi/Library/Application Support/Kaspawallet/kaspa-testnet-10/keys.json"
	minChangeTarget = constants.SompiPerKaspa * 10
)

type walletUTXO struct {
	Outpoint  *externalapi.DomainOutpoint
	UTXOEntry externalapi.UTXOEntry
	address   *walletAddress
}

type walletAddress struct {
	index         uint32
	cosignerIndex uint32
	keyChain      uint8
}

type balancesType struct{ available, pending uint64 }
type balancesMapType map[*walletAddress]*balancesType

func main() {

	address := "kaspatest:qp96y8xa6gqlh3a5c6wu9x73a5egvsw2vk7w7nzm8x98wvkavjlg29zvta4m6"

	client, err := connectToRPC("localhost:16210", 30)
	if err != nil {
		log.Fatal(fmt.Sprintf("error connecting to the RPC server: %s", err))
		return
	}

	defer client.Disconnect()

	estimate, err := client.GetFeeEstimate()
	if err != nil {
		log.Fatal(fmt.Sprintf("error estimating fee: %s", err))
	}
	feeRate := estimate.Estimate.NormalBuckets[0].Feerate
	// Default to a bound of max 1 KAS as fee
	maxFee := uint64(constants.SompiPerKaspa)

	// make sure address string is correct before proceeding to a
	// potentially long UTXO refreshment operation
	toAddress, err := util.DecodeAddress(address, util.Bech32PrefixKaspaTest)
	if err != nil {
		log.Fatal(fmt.Sprintf("error decoding address: %s", err))
	}

	changeAddress, changeWalletAddress, err := changeAddress(keysPath)
	if err != nil {
		log.Fatal(fmt.Sprintf("error getting change address: %s", err))
	}
	var fromAddresses []*walletAddress

	dagInfo, err := client.GetBlockDAGInfo()
	if err != nil {
		log.Fatal(fmt.Sprintf("error getting dag info: %s", err))
	}

	getUTXOsByAddressesResponse, err := client.GetUTXOsByAddresses([]string{address})
	if err != nil {
		log.Fatal(fmt.Sprintf("error getting utxo : %s", err))
	}

	utxos := make([]*walletUTXO, 0, len(getUTXOsByAddressesResponse.Entries))

	for _, entry := range getUTXOsByAddressesResponse.Entries {
		outpoint, err := appmessage.RPCOutpointToDomainOutpoint(entry.Outpoint)
		if err != nil {
			log.Fatal(fmt.Sprintf("error getting dag info: %s", err))
		}

		utxoEntry, err := appmessage.RPCUTXOEntryToUTXOEntry(entry.UTXOEntry)
		if err != nil {
			log.Fatal(fmt.Sprintf("error getting utxentry: %s", err))
		}

		utxos = append(utxos, &walletUTXO{
			Outpoint:  outpoint,
			UTXOEntry: utxoEntry,
			address:   changeWalletAddress,
		})
	}
	sort.Slice(utxos, func(i, j int) bool { return utxos[i].UTXOEntry.Amount() > utxos[j].UTXOEntry.Amount() })

	selectedUTXOs, spendValue, changeSompi, err := selectUTXOs(utxos, dagInfo, uint64(1), false, feeRate, maxFee, fromAddresses)
	if err != nil {
		log.Fatal(fmt.Sprintf("error selecting utxos: %s", err))
	}

	if len(selectedUTXOs) == 0 {
		log.Fatal("couldn't find funds to spend")
	}

	payments := []*libkaspawallet.Payment{{
		Address: toAddress,
		Amount:  spendValue,
	}}
	if changeSompi > 0 {
		payments = append(payments, &libkaspawallet.Payment{
			Address: changeAddress,
			Amount:  changeSompi,
		})
	}
	keysFile, err := keys.ReadKeysFile(&dagconfig.Params{}, keysPath)
	if err != nil {

		log.Fatal("Error reading keys file %s", keysPath)
	}
	unsignedTransaction, err := libkaspawallet.CreateUnsignedTransaction(keysFile.ExtendedPublicKeys,
		keysFile.MinimumSignatures,
		payments, selectedUTXOs)
	if err != nil {
		log.Fatal(fmt.Sprintf("error creating unsignex txs: %s", err))
	}

	mnemonics, err := keysFile.DecryptMnemonics("L1cinda_14")
	if err != nil {
		if strings.Contains(err.Error(), "message authentication failed") {
			fmt.Fprintf(os.Stderr, "Password decryption failed. Sometimes this is a result of not "+
				"specifying the same keys file used by the wallet daemon process.\n")
		}
		log.Fatal(fmt.Sprintf("error mnemonic: %s", err))
	}

	splitTx, err := maybeAutoCompoundTransaction(unsignedTransaction)
	if err != nil {
		log.Fatal(fmt.Sprintf("error sign: %s", err))
	}
	signedTransaction, err := libkaspawallet.Sign(&dagconfig.TestnetParams, mnemonics, splitTx, keysFile.ECDSA)
	if err != nil {
		log.Fatal(fmt.Sprintf("error sign: %s", err))
	}

	fmt.Printf("Broadcasting %s transaction(s)\n", signedTransaction)
	// Since we waited for user input when getting the password, which could take unbound amount of time -
	// create a new context for broadcast, to reset the timeout.
	/*broadcastCtx, broadcastCancel := context.WithTimeout(context.Background(), time.Second*30)
	defer broadcastCancel()

	chunk := [][]byte{signedTransaction}
	response, err := daemonClient.Broadcast(broadcastCtx, &pb.BroadcastRequest{Transactions: chunk})
	if err != nil {
		log.Fatal(fmt.Sprintf("error broadcast: %s", err))
	}
	fmt.Printf("Broadcasted %d transaction(s) (broadcasted %.2f%% of the transactions so far)\n", len(chunk), 100*float64(1)/float64(1))
	fmt.Println("Broadcasted Transaction ID(s): ")
	for _, txID := range response.TxIDs {
		fmt.Printf("\t%s\n", txID)
	}
	if conf.Verbose {
		fmt.Println("Serialized Transaction(s) (can be parsed via the `parse` command or resent via `broadcast`): ")
		for _, signedTx := range signedTransactions {
			fmt.Printf("\t%x\n\n", signedTx)
		}
	}*/

}

func connectToRPC(rpcAddress string, timeout uint32) (*rpcclient.RPCClient, error) {

	rpcClient, err := rpcclient.NewRPCClient(rpcAddress)
	if err != nil {
		return nil, err
	}

	if timeout != 0 {
		rpcClient.SetTimeout(time.Duration(timeout) * time.Second)
	}

	return rpcClient, err
}

func changeAddress(keysFilePath string) (util.Address, *walletAddress, error) {
	var walletAddr *walletAddress

	keysFile, err := keys.ReadKeysFile(&dagconfig.Params{}, keysFilePath)
	if err != nil {
		return nil, nil, err
	}

	internalIndex := uint32(0)
	err = keysFile.SetLastUsedInternalIndex(keysFile.LastUsedInternalIndex() + 1)
	if err != nil {
		return nil, nil, err
	}

	err = keysFile.Save()
	if err != nil {
		return nil, nil, err
	}

	internalIndex = keysFile.LastUsedInternalIndex()

	walletAddr = &walletAddress{
		index:         internalIndex,
		cosignerIndex: keysFile.CosignerIndex,
		keyChain:      libkaspawallet.InternalKeychain,
	}

	path := walletAddressPath(walletAddr)
	address, err := p2pkAddress(keysFile.ExtendedPublicKeys[0], path, keysFile.ECDSA)
	if err != nil {
		return nil, nil, err
	}
	return address, walletAddr, nil
}

func p2pkAddress(extendedPublicKey string, path string, ecdsa bool) (util.Address, error) {
	extendedKey, err := bip32.DeserializeExtendedKey(extendedPublicKey)
	if err != nil {
		return nil, err
	}

	derivedKey, err := extendedKey.DeriveFromPath(path)
	if err != nil {
		return nil, err
	}

	publicKey, err := derivedKey.PublicKey()
	if err != nil {
		return nil, err
	}

	if ecdsa {
		serializedECDSAPublicKey, err := publicKey.Serialize()
		if err != nil {
			return nil, err
		}
		return util.NewAddressPublicKeyECDSA(serializedECDSAPublicKey[:], util.Bech32PrefixKaspaTest)
	}

	schnorrPublicKey, err := publicKey.ToSchnorr()
	if err != nil {
		return nil, err
	}

	serializedSchnorrPublicKey, err := schnorrPublicKey.Serialize()
	if err != nil {
		return nil, err
	}

	return util.NewAddressPublicKey(serializedSchnorrPublicKey[:], util.Bech32PrefixKaspaTest)
}

func selectUTXOs(utxosSortedByAmount []*walletUTXO, dagInfo *appmessage.GetBlockDAGInfoResponseMessage, spendAmount uint64, isSendAll bool, feeRate float64, maxFee uint64, fromAddresses []*walletAddress) (
	selectedUTXOs []*libkaspawallet.UTXO, totalReceived uint64, changeSompi uint64, err error) {

	totalValue := uint64(0)

	var fee uint64
	iteration := func(utxo *walletUTXO) (bool, error) {
		if (fromAddresses != nil && !walletAddressesContain(fromAddresses, utxo.address)) ||
			!isUTXOSpendable(utxo, dagInfo.VirtualDAAScore) {
			return true, nil
		}

		selectedUTXOs = append(selectedUTXOs, &libkaspawallet.UTXO{
			Outpoint:       utxo.Outpoint,
			UTXOEntry:      utxo.UTXOEntry,
			DerivationPath: walletAddressPath(utxo.address),
		})

		totalValue += utxo.UTXOEntry.Amount()
		estimatedRecipientValue := spendAmount
		if isSendAll {
			estimatedRecipientValue = totalValue
		}

		fee, err = estimateFee(selectedUTXOs, feeRate, maxFee, estimatedRecipientValue)
		if err != nil {
			return false, err
		}

		totalSpend := spendAmount + fee
		// Two break cases (if not send all):
		// 		1. totalValue == totalSpend, so there's no change needed -> number of outputs = 1, so a single input is sufficient
		// 		2. totalValue > totalSpend, so there will be change and 2 outputs, therefor in order to not struggle with --
		//		   2.1 go-nodes dust patch we try and find at least 2 inputs (even though the next one is not necessary in terms of spend value)
		// 		   2.2 KIP9 we try and make sure that the change amount is not too small
		if !isSendAll && (totalValue == totalSpend || (totalValue >= totalSpend+minChangeTarget && len(selectedUTXOs) > 1)) {
			return false, nil
		}

		return true, nil
	}

	for _, utxo := range utxosSortedByAmount {
		shouldContinue, err := iteration(utxo)
		if err != nil {
			return nil, 0, 0, err
		}

		if !shouldContinue {
			break
		}
	}

	var totalSpend uint64

	totalSpend = spendAmount + fee
	totalReceived = spendAmount

	if totalValue < totalSpend {
		return nil, 0, 0, fmt.Errorf("Insufficient funds for send: %f required, while only %f available",
			float64(totalSpend)/constants.SompiPerKaspa, float64(totalValue)/constants.SompiPerKaspa)
	}

	return selectedUTXOs, totalReceived, totalValue - totalSpend, nil

}

func walletAddressesContain(addresses []*walletAddress, contain *walletAddress) bool {
	for _, address := range addresses {
		if *address == *contain {
			return true
		}
	}

	return false
}

func isUTXOSpendable(entry *walletUTXO, virtualDAAScore uint64) bool {
	if !entry.UTXOEntry.IsCoinbase() {
		return true
	}
	return entry.UTXOEntry.BlockDAAScore()+100 < virtualDAAScore
}

func walletAddressPath(wAddr *walletAddress) string {
	return fmt.Sprintf("m/%d/%d", wAddr.keyChain, wAddr.index)
}

func estimateFee(selectedUTXOs []*libkaspawallet.UTXO, feeRate float64, maxFee uint64, recipientValue uint64) (uint64, error) {
	keysFile, err := keys.ReadKeysFile(&dagconfig.Params{}, keysPath)
	if err != nil {
		return 0, err
	}

	fakePubKey := [util.PublicKeySizeECDSA]byte{}
	fakeAddr, err := util.NewAddressPublicKeyECDSA(fakePubKey[:], util.Bech32PrefixKaspaTest) // We assume the worst case where the recipient address is ECDSA. In this case the scriptPubKey will be the longest.
	if err != nil {
		return 0, err
	}

	totalValue := uint64(0)
	for _, utxo := range selectedUTXOs {
		totalValue += utxo.UTXOEntry.Amount()
	}

	// This is an approximation for the distribution of value between the recipient output and the change output.
	var mockPayments []*libkaspawallet.Payment
	if totalValue > recipientValue {
		mockPayments = []*libkaspawallet.Payment{
			{
				Address: fakeAddr,
				Amount:  recipientValue,
			},
			{
				Address: fakeAddr,
				Amount:  totalValue - recipientValue, // We ignore the fee since we expect it to be insignificant in mass calculation.
			},
		}
	} else {
		mockPayments = []*libkaspawallet.Payment{
			{
				Address: fakeAddr,
				Amount:  totalValue,
			},
		}
	}

	mockTx, err := libkaspawallet.CreateUnsignedTransaction(keysFile.ExtendedPublicKeys,
		keysFile.MinimumSignatures,
		mockPayments, selectedUTXOs)
	if err != nil {
		return 0, err
	}

	mass, err := server.EstimateMassAfterSignatures(mockTx, keysFile.ECDSA, keysFile.MinimumSignatures, txmass.NewCalculator(1, 10, 1000))
	if err != nil {
		return 0, err
	}

	return min(uint64(math.Ceil(float64(mass)*feeRate)), maxFee), nil
}

func maybeAutoCompoundTransaction(transaction *serialization.PartiallySignedTransaction) ([]byte, error) {

	splitTransactionsBytes, err := serialization.SerializePartiallySignedTransaction(transaction)
	if err != nil {
		return nil, err
	}
	return splitTransactionsBytes, nil
}
