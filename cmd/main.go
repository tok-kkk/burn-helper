package main

import (
	"log"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	burn_helper "tokk-kkk/burn-helper"
)

func main() {
	// txHash pack.Bytes, logNonce, logAmount *big.Int, to []byte
	hash := common.HexToHash("0xf1c638c10c4850968ada8e2425440ddf542c784f0c7616bd9fa82a1a182643ea")
	nonce := big.NewInt(7785)
	amount := big.NewInt(18756964)
	to := []byte("bc1qvfd3fxy35q4894ujcutk6hrqpspn5287ft8ly76nw77nmzcwspqszxlhnx")
	renhash, err := burn_helper.RenHashFromBurnEvent(hash.Bytes(), nonce, amount, to)
	if err != nil {
		panic(err)
	}
	log.Printf("ren hash = %v", renhash)
}
