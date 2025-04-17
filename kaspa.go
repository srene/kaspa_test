package main

import (

	// Replace with actual path

	"fmt"
	"log"
	"time"

	"github.com/kaspanet/kaspad/domain/consensus/model/externalapi"
	"github.com/kaspanet/kaspad/infrastructure/network/rpcclient"
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

	client, err := connectToRPC("localhost:16210", 30)
	if err != nil {
		log.Fatal(fmt.Sprintf("error connecting to the RPC server: %s", err))
		return
	}

	defer client.Disconnect()

	dagInfo, err := client.GetBlockDAGInfo()
	if err != nil {
		log.Fatal(fmt.Sprintf("error getting dagInfo: %s", err))
	}
	daaScore := dagInfo.VirtualDAAScore
	balancesMap := make(balancesMapType, 0)
	for _, entry := range s.utxosSortedByAmount {
		amount := entry.UTXOEntry.Amount()
		address := entry.address
		balances, ok := balancesMap[address]
		if !ok {
			balances = new(balancesType)
			balancesMap[address] = balances
		}
		if s.isUTXOSpendable(entry, daaScore) {
			balances.available += amount
		} else {
			balances.pending += amount
		}
	}
	fmt.Println("dag info:", dagInfo.BlockCount)
	/*infoMessage, err := client.Post(&protowire.KaspadMessage{Payload: &protowire.KaspadMessage_GetInfoRequest{GetInfoRequest: &protowire.GetInfoRequestMessage{}}})
	if err != nil {
		log.Fatal(fmt.Sprintf("Cannot post GetInfo message: %s", err))
		return
	}
	//fmt.Println("Remote version:", infoMessage.GetGetInfoResponse().ServerVersion)

	txRequest := &protowire.KaspadMessage{
		Payload: &protowire.KaspadMessage_SubmitTransactionRequest{
			SubmitTransactionRequest: &protowire.SubmitTransactionRequestMessage{
				Transaction: &protowire.RpcTransaction{},
				AllowOrphan: true,
			},
		},
	}
	txMessage, err := client.Post(txRequest)
	if err != nil {
		log.Fatal(fmt.Sprintf("Cannot post GetInfo message: %s", err))
		return
	}

	fmt.Println("Remote version:", txMessage.GetRequestTransactions().String())*/

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
