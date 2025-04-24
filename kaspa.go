package main

import (

	// Replace with actual path

	"fmt"
	"log"
	"time"

	"github.com/kaspanet/kaspad/cmd/kaspawallet/keys"
	"github.com/kaspanet/kaspad/domain/consensus/model/externalapi"
	"github.com/kaspanet/kaspad/domain/dagconfig"
	"github.com/kaspanet/kaspad/infrastructure/network/rpcclient"
	"github.com/kaspanet/kaspad/util/txmass"
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

	rpcClient, err := connectToRPC("localhost:16210", 30)
	if err != nil {
		log.Fatal(fmt.Sprintf("error connecting to the RPC server: %s", err))
		return
	}

	//defer rpcClient.Disconnect()

	keysFile, err := keys.ReadKeysFile(&dagconfig.Params{}, keysPath)
	if err != nil {

		log.Fatal("Error reading keys file %s", keysPath)
	}

	kaspaClient := &Client{
		rpcClient:          rpcClient,
		coinbaseMaturity:   100,
		keysFile:           keysFile,
		params:             &dagconfig.TestnetParams,
		nextSyncStartIndex: 0,
		addressSet:         make(walletAddressSet),
		txMassCalculator:   txmass.NewCalculator(1, 10, 1000),
		usedOutpoints:      map[externalapi.DomainOutpoint]time.Time{},
	}

	err = kaspaClient.Send(address, "1")
	if err != nil {
		log.Fatal("Error sending %s", err)

	}

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

/*func changeAddress(keysFilePath string) (util.Address, *walletAddress, error) {
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

func maybeAutoCompoundTransaction(transaction *serialization.PartiallySignedTransaction, toAddress util.Address,
	changeAddress util.Address, changeWalletAddress *walletAddress, feeRate float64, maxFee uint64) ([][]byte, error) {

	splitTransactions, err := maybeSplitAndMergeTransaction(transaction, toAddress, changeAddress, changeWalletAddress, feeRate, maxFee)
	if err != nil {
		return nil, err
	}
	splitTransactionsBytes := make([][]byte, len(splitTransactions))
	for i, splitTransaction := range splitTransactions {
		splitTransactionsBytes[i], err = serialization.SerializePartiallySignedTransaction(splitTransaction)
		if err != nil {
			return nil, err
		}
	}
	return splitTransactionsBytes, nil

	/*splitTransactionsBytes, err := serialization.SerializePartiallySignedTransaction(transaction)
	if err != nil {
		return nil, err
	}
	return splitTransactionsBytes, nil*/
/*}

func maybeSplitAndMergeTransaction(transaction *serialization.PartiallySignedTransaction, toAddress util.Address,
	changeAddress util.Address, changeWalletAddress *walletAddress, feeRate float64, maxFee uint64) ([]*serialization.PartiallySignedTransaction, error) {

	err := checkTransactionFeeRate(transaction, maxFee)
	if err != nil {
		return nil, err
	}

	transactionMass, err := s.estimateComputeMassAfterSignatures(transaction)
	if err != nil {
		return nil, err
	}

	if transactionMass < mempool.MaximumStandardTransactionMass {
		return []*serialization.PartiallySignedTransaction{transaction}, nil
	}

	splitCount, inputCountPerSplit, err := splitAndInputPerSplitCounts(transaction, transactionMass, changeAddress, feeRate, maxFee)
	if err != nil {
		return nil, err
	}

	splitTransactions := make([]*serialization.PartiallySignedTransaction, splitCount)
	for i := 0; i < splitCount; i++ {
		startIndex := i * inputCountPerSplit
		endIndex := startIndex + inputCountPerSplit
		var err error
		splitTransactions[i], err = createSplitTransaction(transaction, changeAddress, startIndex, endIndex, feeRate, maxFee)
		if err != nil {
			return nil, err
		}

		err = checkTransactionFeeRate(splitTransactions[i], maxFee)
		if err != nil {
			return nil, err
		}
	}

	if len(splitTransactions) > 1 {
		mergeTransaction, err := mergeTransaction(splitTransactions, transaction, toAddress, changeAddress, changeWalletAddress, feeRate, maxFee)
		if err != nil {
			return nil, err
		}
		// Recursion will be 2-3 iterations deep even in the rarest` cases, so considered safe..
		splitMergeTransaction, err := maybeSplitAndMergeTransaction(mergeTransaction, toAddress, changeAddress, changeWalletAddress, feeRate, maxFee)
		if err != nil {
			return nil, err
		}
		splitTransactions = append(splitTransactions, splitMergeTransaction...)

	}

	return splitTransactions, nil
}

// splitAndInputPerSplitCounts calculates the number of splits to create, and the number of inputs to assign per split.
func splitAndInputPerSplitCounts(transaction *serialization.PartiallySignedTransaction, transactionMass uint64,
	changeAddress util.Address, feeRate float64, maxFee uint64) (splitCount, inputsPerSplitCount int, err error) {
	txMassCalculator := txmass.NewCalculator(1, 10, 1000)
	// Create a dummy transaction which is a clone of the original transaction, but without inputs,
	// to calculate how much mass do all the inputs have
	transactionWithoutInputs := transaction.Tx.Clone()
	transactionWithoutInputs.Inputs = []*externalapi.DomainTransactionInput{}
	massWithoutInputs := txMassCalculator.CalculateTransactionMass(transactionWithoutInputs)

	massOfAllInputs := transactionMass - massWithoutInputs

	// Since the transaction was generated by kaspawallet, we assume all inputs have the same number of signatures, and
	// thus - the same mass.
	inputCount := len(transaction.Tx.Inputs)
	massPerInput := massOfAllInputs / uint64(inputCount)
	if massOfAllInputs%uint64(inputCount) > 0 {
		massPerInput++
	}

	// Create another dummy transaction, this time one similar to the split transactions we wish to generate,
	// but with 0 inputs, to calculate how much mass for inputs do we have available in the split transactions
	splitTransactionWithoutInputs, err := createSplitTransaction(transaction, changeAddress, 0, 0, feeRate, maxFee)
	if err != nil {
		return 0, 0, err
	}
	massForEverythingExceptInputsInSplitTransaction :=
		txMassCalculator.CalculateTransactionMass(splitTransactionWithoutInputs.Tx)
	massForInputsInSplitTransaction := mempool.MaximumStandardTransactionMass - massForEverythingExceptInputsInSplitTransaction

	inputsPerSplitCount = int(massForInputsInSplitTransaction / massPerInput)
	splitCount = inputCount / inputsPerSplitCount
	if inputCount%inputsPerSplitCount > 0 {
		splitCount++
	}

	return splitCount, inputsPerSplitCount, nil
}

func createSplitTransaction(transaction *serialization.PartiallySignedTransaction,
	changeAddress util.Address, startIndex int, endIndex int, feeRate float64, maxFee uint64) (*serialization.PartiallySignedTransaction, error) {

	selectedUTXOs := make([]*libkaspawallet.UTXO, 0, endIndex-startIndex)
	totalSompi := uint64(0)

	keysFile, err := keys.ReadKeysFile(&dagconfig.Params{}, keysPath)
	if err != nil {
		return nil, err
	}

	for i := startIndex; i < endIndex && i < len(transaction.PartiallySignedInputs); i++ {
		partiallySignedInput := transaction.PartiallySignedInputs[i]
		selectedUTXOs = append(selectedUTXOs, &libkaspawallet.UTXO{
			Outpoint: &transaction.Tx.Inputs[i].PreviousOutpoint,
			UTXOEntry: utxo.NewUTXOEntry(
				partiallySignedInput.PrevOutput.Value, partiallySignedInput.PrevOutput.ScriptPublicKey,
				false, constants.UnacceptedDAAScore),
			DerivationPath: partiallySignedInput.DerivationPath,
		})

		totalSompi += selectedUTXOs[i-startIndex].UTXOEntry.Amount()
	}
	if len(selectedUTXOs) != 0 {
		fee, err := estimateFee(selectedUTXOs, feeRate, maxFee, totalSompi)
		if err != nil {
			return nil, err
		}

		totalSompi -= fee
	}

	return libkaspawallet.CreateUnsignedTransaction(keysFile.ExtendedPublicKeys,
		keysFile.MinimumSignatures,
		[]*libkaspawallet.Payment{{
			Address: changeAddress,
			Amount:  totalSompi,
		}}, selectedUTXOs)
}

func checkTransactionFeeRate(psTx *serialization.PartiallySignedTransaction, maxFee uint64) error {
	feeRate, err := transactionFeeRate(psTx)
	if err != nil {
		return err
	}

	if feeRate < 1 {
		return errors.Errorf("setting --max-fee to %d results in a fee rate of %f, which is below the minimum allowed fee rate of 1 sompi/gram", maxFee, feeRate)
	}

	return nil
}

func transactionFeeRate(psTx *serialization.PartiallySignedTransaction) (float64, error) {
	totalOuts := 0
	for _, output := range psTx.Tx.Outputs {
		totalOuts += int(output.Value)
	}

	totalIns := 0
	for _, input := range psTx.PartiallySignedInputs {
		totalIns += int(input.PrevOutput.Value)
	}

	if totalIns < totalOuts {
		return 0, errors.Errorf("Transaction don't have enough funds to pay for the outputs")
	}
	fee := totalIns - totalOuts
	keysFile, err := keys.ReadKeysFile(&dagconfig.Params{}, keysPath)
	if err != nil {
		return 0, err
	}
	txMassCalculator := txmass.NewCalculator(1, 10, 1000)

	mass, err := estimateComputeMassAfterSignatures(psTx, keysFile.ECDSA, keysFile.MinimumSignatures, txMassCalculator)
	if err != nil {
		return 0, err
	}
	return float64(fee) / float64(mass), nil
}

func estimateComputeMassAfterSignatures(transaction *serialization.PartiallySignedTransaction, ecdsa bool, minimumSignatures uint32, txMassCalculator *txmass.Calculator) (uint64, error) {
	transactionWithSignatures, err := createTransactionWithJunkFieldsForMassCalculation(transaction, ecdsa, minimumSignatures, txMassCalculator)
	if err != nil {
		return 0, err
	}

	return txMassCalculator.CalculateTransactionMass(transactionWithSignatures), nil
}

func createTransactionWithJunkFieldsForMassCalculation(transaction *serialization.PartiallySignedTransaction, ecdsa bool, minimumSignatures uint32, txMassCalculator *txmass.Calculator) (*externalapi.DomainTransaction, error) {
	transaction = transaction.Clone()
	var signatureSize uint64
	if ecdsa {
		signatureSize = secp256k1.SerializedECDSASignatureSize
	} else {
		signatureSize = secp256k1.SerializedSchnorrSignatureSize
	}

	for i, input := range transaction.PartiallySignedInputs {
		for j, pubKeyPair := range input.PubKeySignaturePairs {
			if uint32(j) >= minimumSignatures {
				break
			}
			pubKeyPair.Signature = make([]byte, signatureSize+1) // +1 for SigHashType
		}
		transaction.Tx.Inputs[i].SigOpCount = byte(len(input.PubKeySignaturePairs))
	}

	return libkaspawallet.ExtractTransactionDeserialized(transaction, ecdsa)
}

func mergeTransaction(
	splitTransactions []*serialization.PartiallySignedTransaction,
	originalTransaction *serialization.PartiallySignedTransaction,
	toAddress util.Address,
	changeAddress util.Address,
	changeWalletAddress *walletAddress,
	feeRate float64,
	maxFee uint64,
) (*serialization.PartiallySignedTransaction, error) {
	numOutputs := len(originalTransaction.Tx.Outputs)
	if numOutputs > 2 || numOutputs == 0 {
		// This is a sanity check to make sure originalTransaction has either 1 or 2 outputs:
		// 1. For the payment itself
		// 2. (optional) for change
		return nil, errors.Errorf("original transaction has %d outputs, while 1 or 2 are expected",
			len(originalTransaction.Tx.Outputs))
	}
	keysFile, err := keys.ReadKeysFile(&dagconfig.Params{}, keysPath)
	if err != nil {

		log.Fatal("Error reading keys file %s", keysPath)
	}
	totalValue := uint64(0)
	sentValue := originalTransaction.Tx.Outputs[0].Value
	utxos := make([]*libkaspawallet.UTXO, len(splitTransactions))
	for i, splitTransaction := range splitTransactions {
		output := splitTransaction.Tx.Outputs[0]
		utxos[i] = &libkaspawallet.UTXO{
			Outpoint: &externalapi.DomainOutpoint{
				TransactionID: *consensushashing.TransactionID(splitTransaction.Tx),
				Index:         0,
			},
			UTXOEntry:      utxo.NewUTXOEntry(output.Value, output.ScriptPublicKey, false, constants.UnacceptedDAAScore),
			DerivationPath: walletAddressPath(changeWalletAddress),
		}
		totalValue += output.Value
	}
	// We're overestimating a bit by assuming that any transaction will have a change output
	fee, err := estimateFee(utxos, feeRate, maxFee, sentValue)
	if err != nil {
		return nil, err
	}

	totalValue -= fee

	if totalValue < sentValue {
		// sometimes the fees from compound transactions make the total output higher than what's available from selected
		// utxos, in such cases - find one more UTXO and use it.
		additionalUTXOs, totalValueAdded, err := moreUTXOsForMergeTransaction(utxos, sentValue-totalValue, feeRate)
		if err != nil {
			return nil, err
		}
		utxos = append(utxos, additionalUTXOs...)
		totalValue += totalValueAdded
	}

	payments := []*libkaspawallet.Payment{{
		Address: toAddress,
		Amount:  sentValue,
	}}
	if totalValue > sentValue {
		payments = append(payments, &libkaspawallet.Payment{
			Address: changeAddress,
			Amount:  totalValue - sentValue,
		})
	}

	return libkaspawallet.CreateUnsignedTransaction(keysFile.ExtendedPublicKeys,
		keysFile.MinimumSignatures, payments, utxos)
}

func moreUTXOsForMergeTransaction(alreadySelectedUTXOs []*libkaspawallet.UTXO, requiredAmount uint64, feeRate float64) (
	additionalUTXOs []*libkaspawallet.UTXO, totalValueAdded uint64, err error) {

	dagInfo, err := s.rpcClient.GetBlockDAGInfo()
	if err != nil {
		return nil, 0, err
	}
	alreadySelectedUTXOsMap := make(map[externalapi.DomainOutpoint]struct{}, len(alreadySelectedUTXOs))
	for _, alreadySelectedUTXO := range alreadySelectedUTXOs {
		alreadySelectedUTXOsMap[*alreadySelectedUTXO.Outpoint] = struct{}{}
	}

	feePerInput, err := estimateFeePerInput(feeRate)
	if err != nil {
		return nil, 0, err
	}

	for _, utxo := range s.utxosSortedByAmount {
		if _, ok := alreadySelectedUTXOsMap[*utxo.Outpoint]; ok {
			continue
		}
		if !s.isUTXOSpendable(utxo, dagInfo.VirtualDAAScore) {
			continue
		}
		additionalUTXOs = append(additionalUTXOs, &libkaspawallet.UTXO{
			Outpoint:       utxo.Outpoint,
			UTXOEntry:      utxo.UTXOEntry,
			DerivationPath: s.walletAddressPath(utxo.address)})
		totalValueAdded += utxo.UTXOEntry.Amount() - feePerInput
		if totalValueAdded >= requiredAmount {
			break
		}
	}
	if totalValueAdded < requiredAmount {
		return nil, 0, errors.Errorf("Insufficient funds for merge transaction")
	}

	return additionalUTXOs, totalValueAdded, nil
}*/
