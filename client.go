package main

import (
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/kaspanet/kaspad/app/appmessage"
	"github.com/kaspanet/kaspad/cmd/kaspawallet/daemon/pb"
	"github.com/kaspanet/kaspad/cmd/kaspawallet/keys"
	"github.com/kaspanet/kaspad/cmd/kaspawallet/libkaspawallet"
	"github.com/kaspanet/kaspad/cmd/kaspawallet/utils"
	"github.com/kaspanet/kaspad/domain/consensus/model/externalapi"
	"github.com/kaspanet/kaspad/domain/consensus/utils/constants"
	"github.com/kaspanet/kaspad/domain/consensus/utils/utxo"
	"github.com/kaspanet/kaspad/domain/dagconfig"
	"github.com/kaspanet/kaspad/infrastructure/network/rpcclient"
	"github.com/kaspanet/kaspad/util"
	"github.com/kaspanet/kaspad/util/txmass"
	"github.com/pkg/errors"
)

const (
	keysPath        = "/Users/sergi/Library/Application Support/Kaspawallet/kaspa-testnet-10/keys.json"
	minChangeTarget = constants.SompiPerKaspa * 10
	minFeeRate      = 1.0
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
}

func (c *Client) Send(address string, amount string) error {

	sendAmountSompi, err := utils.KasToSompi(amount)
	if err != nil {
		return err
	}

	c.refreshUTXOs()

	unsignedTransactions, err := c.createUnsignedTransactions(address, sendAmountSompi, false,
		[]string{}, false, nil)
	if err != nil {
		return err
	}

	mnemonics, err := c.keysFile.DecryptMnemonics("L1cinda_14")
	if err != nil {
		if strings.Contains(err.Error(), "message authentication failed") {
			fmt.Fprintf(os.Stderr, "Password decryption failed. Sometimes this is a result of not "+
				"specifying the same keys file used by the wallet daemon process.\n")
		}
		return err
	}

	fmt.Println(mnemonics)

	signedTransactions := make([][]byte, len(unsignedTransactions))
	for i, unsignedTransaction := range unsignedTransactions {
		fmt.Println(hex.EncodeToString(unsignedTransaction))

		signedTransaction, err := libkaspawallet.Sign(&dagconfig.TestnetParams, mnemonics, unsignedTransaction, false)
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

	fmt.Println("Serialized Transaction(s) (can be parsed via the `parse` command or resent via `broadcast`): ")
	for _, signedTx := range signedTransactions {
		fmt.Printf("\t%x\n\n", signedTx)
	}
	return nil
	/*c.Send(address, sendAmountSompi)

	estimate, err := c.GetFeeEstimate()
	if err != nil {
		return err
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

	selectedUTXOs, spendValue, changeSompi, err := selectUTXOs(utxos, dagInfo, uint64(10000000), false, feeRate, maxFee, fromAddresses)
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
	fmt.Println("utx2", len(splitTx), hex.EncodeToString(splitTx))

	fmt.Println(mnemonics)
	fmt.Println(hex.EncodeToString(splitTx))
	signedTransaction, err := libkaspawallet.Sign(&dagconfig.TestnetParams, mnemonics, splitTx, keysFile.ECDSA)
	if err != nil {
		log.Fatal(fmt.Sprintf("error sign: %s", err))
	}

	fmt.Printf("signedtx", hex.EncodeToString(signedTransaction))

	tx, err := libkaspawallet.ExtractTransaction(signedTransaction, false)
	if err != nil {
		log.Fatal(fmt.Sprintf("error extract tx: %s", err))
	}

	submitTransactionResponse, err := client.SubmitTransaction(appmessage.DomainTransactionToRPCTransaction(tx), consensushashing.TransactionID(tx).String(), false)
	if err != nil {
		log.Fatal(fmt.Sprintf("error submitting tx: %s", err))
	}

	fmt.Printf("Broadcasting %s transaction(s)\n", submitTransactionResponse.TransactionID)*/
}

func (s *Client) calculateFeeLimits(requestFeePolicy *pb.FeePolicy) (feeRate float64, maxFee uint64, err error) {
	feeRate = minFeeRate
	maxFee = math.MaxUint64

	if requestFeePolicy == nil {
		requestFeePolicy = &pb.FeePolicy{}
	}

	switch requestFeePolicy := requestFeePolicy.FeePolicy.(type) {
	case *pb.FeePolicy_ExactFeeRate:
		feeRate = requestFeePolicy.ExactFeeRate
		if feeRate < minFeeRate {
			return 0, 0, errors.Errorf("requested fee rate %f is too low, minimum fee rate is %f", feeRate, minFeeRate)
		}
	case *pb.FeePolicy_MaxFeeRate:
		estimate, err := s.rpcClient.GetFeeEstimate()
		if err != nil {
			return 0, 0, err
		}
		if requestFeePolicy.MaxFeeRate < minFeeRate {
			return 0, 0, errors.Errorf("requested max fee rate %f is too low, minimum fee rate is %f", requestFeePolicy.MaxFeeRate, minFeeRate)
		}
		feeRate = math.Min(estimate.Estimate.NormalBuckets[0].Feerate, requestFeePolicy.MaxFeeRate)
	case *pb.FeePolicy_MaxFee:
		estimate, err := s.rpcClient.GetFeeEstimate()
		if err != nil {
			return 0, 0, err
		}
		feeRate = estimate.Estimate.NormalBuckets[0].Feerate
		maxFee = requestFeePolicy.MaxFee
	case nil:
		estimate, err := s.rpcClient.GetFeeEstimate()
		if err != nil {
			return 0, 0, err
		}
		feeRate = estimate.Estimate.NormalBuckets[0].Feerate
		// Default to a bound of max 1 KAS as fee
		maxFee = constants.SompiPerKaspa
	}

	return feeRate, maxFee, nil
}

func (s *Client) createUnsignedTransactions(address string, amount uint64, isSendAll bool, fromAddressesString []string, useExistingChangeAddress bool, requestFeePolicy *pb.FeePolicy) ([][]byte, error) {
	/*if !s.isSynced() {
		return nil, errors.Errorf("wallet daemon is not synced yet, %s", s.formatSyncStateReport())
	}*/

	feeRate, maxFee, err := s.calculateFeeLimits(requestFeePolicy)
	if err != nil {
		return nil, err
	}

	// make sure address string is correct before proceeding to a
	// potentially long UTXO refreshment operation
	toAddress, err := util.DecodeAddress(address, s.params.Prefix)
	if err != nil {
		return nil, err
	}

	var fromAddresses []*walletAddress
	for _, from := range fromAddressesString {
		fromAddress, exists := s.addressSet[from]
		if !exists {
			return nil, fmt.Errorf("specified from address %s does not exists", from)
		}
		fromAddresses = append(fromAddresses, fromAddress)
	}

	changeAddress, changeWalletAddress, err := s.changeAddress(useExistingChangeAddress, fromAddresses)
	if err != nil {
		return nil, err
	}

	selectedUTXOs, spendValue, changeSompi, err := s.selectUTXOs(amount, isSendAll, feeRate, maxFee, fromAddresses)
	if err != nil {
		return nil, err
	}

	if len(selectedUTXOs) == 0 {
		return nil, errors.Errorf("couldn't find funds to spend")
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
	unsignedTransaction, err := libkaspawallet.CreateUnsignedTransaction(s.keysFile.ExtendedPublicKeys,
		s.keysFile.MinimumSignatures,
		payments, selectedUTXOs)
	if err != nil {
		return nil, err
	}

	fmt.Println("utx", unsignedTransaction.Tx)
	unsignedTransactions, err := s.maybeAutoCompoundTransaction(unsignedTransaction, toAddress, changeAddress, changeWalletAddress, feeRate, maxFee)
	if err != nil {
		return nil, err
	}
	fmt.Println("utx2", len(unsignedTransactions[0]), hex.EncodeToString(unsignedTransactions[0]))

	return unsignedTransactions, nil
}

func (s *Client) selectUTXOs(spendAmount uint64, isSendAll bool, feeRate float64, maxFee uint64, fromAddresses []*walletAddress) (
	selectedUTXOs []*libkaspawallet.UTXO, totalReceived uint64, changeSompi uint64, err error) {
	return s.selectUTXOsWithPreselected(nil, map[externalapi.DomainOutpoint]struct{}{}, spendAmount, isSendAll, feeRate, maxFee, fromAddresses)
}

func (s *Client) selectUTXOsWithPreselected(preSelectedUTXOs []*walletUTXO, allowUsed map[externalapi.DomainOutpoint]struct{}, spendAmount uint64, isSendAll bool, feeRate float64, maxFee uint64, fromAddresses []*walletAddress) (
	selectedUTXOs []*libkaspawallet.UTXO, totalReceived uint64, changeSompi uint64, err error) {

	preSelectedSet := make(map[externalapi.DomainOutpoint]struct{})
	for _, utxo := range preSelectedUTXOs {
		preSelectedSet[*utxo.Outpoint] = struct{}{}
	}
	totalValue := uint64(0)

	dagInfo, err := s.rpcClient.GetBlockDAGInfo()
	if err != nil {
		return nil, 0, 0, err
	}

	var fee uint64
	iteration := func(utxo *walletUTXO, avoidPreselected bool) (bool, error) {
		if (fromAddresses != nil && !walletAddressesContain(fromAddresses, utxo.address)) ||
			!s.isUTXOSpendable(utxo, dagInfo.VirtualDAAScore) {
			return true, nil
		}

		if broadcastTime, ok := s.usedOutpoints[*utxo.Outpoint]; ok {
			if _, ok := allowUsed[*utxo.Outpoint]; !ok {
				if s.usedOutpointHasExpired(broadcastTime) {
					delete(s.usedOutpoints, *utxo.Outpoint)
				} else {
					return true, nil
				}
			}
		}

		if avoidPreselected {
			if _, ok := preSelectedSet[*utxo.Outpoint]; ok {
				return true, nil
			}
		}

		selectedUTXOs = append(selectedUTXOs, &libkaspawallet.UTXO{
			Outpoint:       utxo.Outpoint,
			UTXOEntry:      utxo.UTXOEntry,
			DerivationPath: s.walletAddressPath(utxo.address),
		})

		totalValue += utxo.UTXOEntry.Amount()
		estimatedRecipientValue := spendAmount
		if isSendAll {
			estimatedRecipientValue = totalValue
		}

		fee, err = s.estimateFee(selectedUTXOs, feeRate, maxFee, estimatedRecipientValue)
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

	shouldContinue := true
	for _, utxo := range preSelectedUTXOs {
		shouldContinue, err = iteration(utxo, false)
		if err != nil {
			return nil, 0, 0, err
		}

		if !shouldContinue {
			break
		}
	}

	if shouldContinue {
		for _, utxo := range s.utxosSortedByAmount {
			shouldContinue, err := iteration(utxo, true)
			if err != nil {
				return nil, 0, 0, err
			}

			if !shouldContinue {
				break
			}
		}
	}

	var totalSpend uint64
	if isSendAll {
		totalSpend = totalValue
		totalReceived = totalValue - fee
	} else {
		totalSpend = spendAmount + fee
		totalReceived = spendAmount
	}
	if totalValue < totalSpend {
		return nil, 0, 0, errors.Errorf("Insufficient funds for send: %f required, while only %f available",
			float64(totalSpend)/constants.SompiPerKaspa, float64(totalValue)/constants.SompiPerKaspa)
	}

	return selectedUTXOs, totalReceived, totalValue - totalSpend, nil
}

func (s *Client) estimateFee(selectedUTXOs []*libkaspawallet.UTXO, feeRate float64, maxFee uint64, recipientValue uint64) (uint64, error) {
	fakePubKey := [util.PublicKeySizeECDSA]byte{}
	fakeAddr, err := util.NewAddressPublicKeyECDSA(fakePubKey[:], s.params.Prefix) // We assume the worst case where the recipient address is ECDSA. In this case the scriptPubKey will be the longest.
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

	mockTx, err := libkaspawallet.CreateUnsignedTransaction(s.keysFile.ExtendedPublicKeys,
		s.keysFile.MinimumSignatures,
		mockPayments, selectedUTXOs)
	if err != nil {
		return 0, err
	}

	mass, err := s.estimateMassAfterSignatures(mockTx)
	if err != nil {
		return 0, err
	}

	return min(uint64(math.Ceil(float64(mass)*feeRate)), maxFee), nil
}

func (s *Client) estimateFeePerInput(feeRate float64) (uint64, error) {
	mockUTXO := &libkaspawallet.UTXO{
		Outpoint: &externalapi.DomainOutpoint{
			TransactionID: externalapi.DomainTransactionID{},
			Index:         0,
		},
		UTXOEntry: utxo.NewUTXOEntry(1, &externalapi.ScriptPublicKey{
			Script:  nil,
			Version: 0,
		}, false, 0),
		DerivationPath: "m",
	}

	mockTx, err := libkaspawallet.CreateUnsignedTransaction(s.keysFile.ExtendedPublicKeys,
		s.keysFile.MinimumSignatures,
		nil, []*libkaspawallet.UTXO{mockUTXO})
	if err != nil {
		return 0, err
	}

	// Here we use compute mass to avoid dividing by zero. This is ok since `s.estimateFeePerInput` is only used
	// in the case of compound transactions that have a compute mass higher than its storage mass.
	mass, err := s.estimateComputeMassAfterSignatures(mockTx)
	if err != nil {
		return 0, err
	}

	mockTxWithoutUTXO, err := libkaspawallet.CreateUnsignedTransaction(s.keysFile.ExtendedPublicKeys,
		s.keysFile.MinimumSignatures,
		nil, nil)
	if err != nil {
		return 0, err
	}

	massWithoutUTXO, err := s.estimateComputeMassAfterSignatures(mockTxWithoutUTXO)
	if err != nil {
		return 0, err
	}

	inputMass := mass - massWithoutUTXO

	return uint64(float64(inputMass) * feeRate), nil
}

func walletAddressesContain(addresses []*walletAddress, contain *walletAddress) bool {
	for _, address := range addresses {
		if *address == *contain {
			return true
		}
	}

	return false
}

func (s *Client) refreshUTXOs() error {

	// No need to lock for reading since the only writer of this set is on `syncLoop` on the same goroutine.
	addresses := s.addressSet.strings()
	// It's important to check the mempool before calling `GetUTXOsByAddresses`:
	// If we would do it the other way around an output can be spent in the mempool
	// and not in consensus, and between the calls its spending transaction will be
	// added to consensus and removed from the mempool, so `getUTXOsByAddressesResponse`
	// will include an obsolete output.
	mempoolEntriesByAddresses, err := s.rpcClient.GetMempoolEntriesByAddresses(addresses, true, true)
	if err != nil {
		return err
	}

	getUTXOsByAddressesResponse, err := s.rpcClient.GetUTXOsByAddresses(addresses)
	if err != nil {
		return err
	}

	return s.updateUTXOSet(getUTXOsByAddressesResponse.Entries, mempoolEntriesByAddresses.Entries)
}

// updateUTXOSet clears the current UTXO set, and re-fills it with the given entries
func (s *Client) updateUTXOSet(entries []*appmessage.UTXOsByAddressesEntry, mempoolEntries []*appmessage.MempoolEntryByAddress) error {
	utxos := make([]*walletUTXO, 0, len(entries))

	exclude := make(map[appmessage.RPCOutpoint]struct{})
	for _, entriesByAddress := range mempoolEntries {
		for _, entry := range entriesByAddress.Sending {
			for _, input := range entry.Transaction.Inputs {
				exclude[*input.PreviousOutpoint] = struct{}{}
			}
		}
	}

	mempoolExcludedUTXOs := make(map[externalapi.DomainOutpoint]*walletUTXO)
	for _, entry := range entries {
		outpoint, err := appmessage.RPCOutpointToDomainOutpoint(entry.Outpoint)
		if err != nil {
			return err
		}

		utxoEntry, err := appmessage.RPCUTXOEntryToUTXOEntry(entry.UTXOEntry)
		if err != nil {
			return err
		}

		// No need to lock for reading since the only writer of this set is on `syncLoop` on the same goroutine.
		address, ok := s.addressSet[entry.Address]
		if !ok {
			return errors.Errorf("Got result from address %s even though it wasn't requested", entry.Address)
		}

		utxo := &walletUTXO{
			Outpoint:  outpoint,
			UTXOEntry: utxoEntry,
			address:   address,
		}

		if _, ok := exclude[*entry.Outpoint]; ok {
			mempoolExcludedUTXOs[*outpoint] = utxo
		} else {
			utxos = append(utxos, &walletUTXO{
				Outpoint:  outpoint,
				UTXOEntry: utxoEntry,
				address:   address,
			})
		}
	}

	sort.Slice(utxos, func(i, j int) bool { return utxos[i].UTXOEntry.Amount() > utxos[j].UTXOEntry.Amount() })
	s.startTimeOfLastCompletedRefresh = time.Now()

	s.utxosSortedByAmount = utxos
	s.mempoolExcludedUTXOs = mempoolExcludedUTXOs

	// Cleanup expired used outpoints to avoid a memory leak
	for outpoint, broadcastTime := range s.usedOutpoints {
		if s.usedOutpointHasExpired(broadcastTime) {
			delete(s.usedOutpoints, outpoint)
		}
	}

	return nil
}

func (s *Client) usedOutpointHasExpired(outpointBroadcastTime time.Time) bool {
	// If the node returns a UTXO we previously attempted to spend and enough time has passed, we assume
	// that the network rejected or lost the previous transaction and allow a reuse. We set this time
	// interval to a minute.
	// We also verify that a full refresh UTXO operation started after this time point and has already
	// completed, in order to make sure that indeed this state reflects a state obtained following the required wait time.
	return s.startTimeOfLastCompletedRefresh.After(outpointBroadcastTime.Add(time.Minute))
}
