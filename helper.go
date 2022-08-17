package burn_helper

import (
	"encoding/binary"
	"fmt"
	"math/big"

	"github.com/btcsuite/btcd/chaincfg"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/renproject/id"
	"github.com/renproject/multichain"
	"github.com/renproject/multichain/chain/bitcoin"
	"github.com/renproject/multichain/chain/bitcoincash"
	"github.com/renproject/multichain/chain/digibyte"
	"github.com/renproject/multichain/chain/dogecoin"
	"github.com/renproject/multichain/chain/ethereum"
	"github.com/renproject/multichain/chain/filecoin"
	"github.com/renproject/multichain/chain/solana"
	"github.com/renproject/multichain/chain/terra"
	"github.com/renproject/multichain/chain/zcash"
	"github.com/renproject/pack"
	"github.com/renproject/surge"
)

var (
	network     = multichain.NetworkMainnet
	asset       = multichain.BTC
	destination = multichain.Bitcoin
	selector    = pack.String("BTC/fromPolygon")
	version     = pack.String("1")
)

func RenHashFromBurnEvent(txHash pack.Bytes, logNonce, logAmount *big.Int, to []byte) (string, error) {
	nonce := pack.NewBytes32(pack.NewU256FromInt(logNonce).Bytes32())
	amount := pack.NewU256FromU64(pack.U64(logAmount.Uint64()))
	addrEncoderDecoder := AddressEncodeDecoder(destination, network)

	toBytes, err := addrEncoderDecoder.DecodeAddress(multichain.Address(to))
	if err != nil {
		return "", err
	}

	txindex := pack.U32(0)
	payload := pack.Bytes{}
	phash := Phash(payload)
	nhash := Nhash(nonce, txHash, txindex)
	ghash := Ghash(selector, phash, toBytes, nonce)
	input, err := pack.Encode(LockMintBurnReleaseInput{
		Txid:    txHash,
		Txindex: txindex,
		Amount:  amount,
		Payload: payload,
		Phash:   phash,
		To:      pack.String(to),
		Nonce:   nonce,
		Nhash:   nhash,
		Gpubkey: pack.Bytes{},
		Ghash:   ghash,
	})
	if err != nil {
		return "", err
	}

	txhash, err := NewTxHash(version, selector, pack.Typed(input.(pack.Struct)))
	if err != nil {
		return "", err
	}

	return txhash.String(), nil
}

func AddressEncodeDecoder(chain multichain.Chain, network multichain.Network) multichain.AddressEncodeDecoder {
	switch chain {
	case multichain.Bitcoin, multichain.DigiByte, multichain.Dogecoin:
		params := NetParams(chain, network)
		return bitcoin.NewAddressEncodeDecoder(params)
	case multichain.BitcoinCash:
		params := NetParams(chain, network)
		return bitcoincash.NewAddressEncodeDecoder(params)
	case multichain.Zcash:
		params := ZcashNetParams(network)
		return zcash.NewAddressEncodeDecoder(params)
	case multichain.Avalanche, multichain.BinanceSmartChain, multichain.Ethereum, multichain.Fantom, multichain.Polygon:
		return ethereum.NewAddressEncodeDecoder()
	case multichain.Filecoin:
		return filecoin.NewAddressEncodeDecoder()
	case multichain.Solana:
		return solana.NewAddressEncodeDecoder()
	case multichain.Terra:
		return terra.NewAddressEncodeDecoder()
	default:
		panic(fmt.Errorf("AddressEncodeDecoder : unknown blockchain %v", chain))
	}
}

// NetParams returns the chain config for the given blockchain and network.
// It will panic for non-utxo-based chains.
func NetParams(chain multichain.Chain, net multichain.Network) *chaincfg.Params {
	switch chain {
	case multichain.Bitcoin, multichain.BitcoinCash:
		switch net {
		case multichain.NetworkMainnet:
			return &chaincfg.MainNetParams
		case multichain.NetworkTestnet:
			return &chaincfg.TestNet3Params
		default:
			return &chaincfg.RegressionNetParams
		}
	case multichain.Zcash:
		switch net {
		case multichain.NetworkMainnet:
			return zcash.MainNetParams.Params
		case multichain.NetworkTestnet:
			return zcash.TestNet3Params.Params
		default:
			return zcash.RegressionNetParams.Params
		}
	case multichain.DigiByte:
		switch net {
		case multichain.NetworkMainnet:
			return &digibyte.MainNetParams
		case multichain.NetworkTestnet:
			return &digibyte.TestnetParams
		default:
			return &digibyte.RegressionNetParams
		}
	case multichain.Dogecoin:
		switch net {
		case multichain.NetworkMainnet:
			return &dogecoin.MainNetParams
		case multichain.NetworkTestnet:
			return &dogecoin.TestNetParams
		default:
			return &dogecoin.RegressionNetParams
		}
	default:
		panic(fmt.Errorf("cannot get network params: unknown chain %v", chain))
	}
}

func ZcashNetParams(net multichain.Network) *zcash.Params {
	switch net {
	case multichain.NetworkMainnet:
		return &zcash.MainNetParams
	case multichain.NetworkTestnet:
		return &zcash.TestNet3Params
	default:
		return &zcash.RegressionNetParams
	}
}

// Phash returns the keccak256 hash of the payload.
func Phash(payload pack.Bytes) pack.Bytes32 {
	if payload == nil {
		payload = pack.Bytes([]byte{})
	}
	// Always use keccak. This is a bit of a legacy requirement, left over from
	// the days when RenVM only supported Ethereum.
	phash := [32]byte{}
	copy(phash[:], crypto.Keccak256(payload))
	return pack.Bytes32(phash)
}

// Ghash returns the keccak256 hash of the phash, shash, to address, and nonce.
// The ghash is embedded into gateway scripts to differentiate between different
// gateways. This also binds the gateway to the phash, shash, to address, and
// nonce.
func Ghash(selector pack.String, phash pack.Bytes32, to multichain.RawAddress, nonce pack.Bytes32) pack.Bytes32 {
	if to == nil {
		to = multichain.RawAddress{}
	}
	shash := Shash(selector)
	ghash := pack.Bytes32{}
	copy(ghash[:], crypto.Keccak256(append(append(append(phash[:], shash[:]...), to...), nonce[:]...)))
	return ghash
}

// Nhash returns the keccak256 hash of the nonce, the txid, and the txindex.
// This is used to produce a once-off "nonce hash" based on the nonce and the
// underlying transaction uniqueness.
func Nhash(nonce pack.Bytes32, txid pack.Bytes, txindex pack.U32) pack.Bytes32 {
	if txid == nil {
		txid = pack.Bytes{}
	}
	nhash := [32]byte{}
	txindexData := [4]byte{}
	binary.BigEndian.PutUint32(txindexData[:], uint32(txindex))
	copy(nhash[:], crypto.Keccak256(append(append(nonce[:], txid...), txindexData[:]...)))
	return pack.Bytes32(nhash)
}

// Shash returns the keccak256 hash of the selector. The selector will be
// marshalled using surge before the hash function is applied.
func Shash(selector pack.String) pack.Bytes32 {
	// Always use keccak. This is a bit of a legacy requirement, left over from
	// the days when RenVM only supported Ethereum.
	compressed := fmt.Sprintf("%v/to%v", asset, destination)
	shash := [32]byte{}
	copy(shash[:], crypto.Keccak256([]byte(compressed)))
	return pack.Bytes32(shash)
}

// LockMintBurnReleaseInput defines the input structure for cross-chain
// transactions. This includes lock-and-mint, burn-and-release, and
// burn-and-mint transactions.
type LockMintBurnReleaseInput struct {
	// Txid of the transaction on the underlying chain that locks/burns assets.
	Txid pack.Bytes `json:"txid"`
	// Index into the transaction on the underlying chain. This index identifies
	// the part of the transaction that is locking/burning assets.
	Txindex pack.U32 `json:"txindex"`
	// Amount of assets being locked/burned. In the case of lock-and-mint tx,
	// amount signifies the value received by the gateway address (in case of
	// locking a UTXO asset) or RenVM's address (in case of locking an Account
	// asset). In the case of burn-and-release tx, amount signifies the tokens
	// burned by the user as logged by the host chain's smart contract, eg. in the
	// case of burning renBTC on Ethereum, amount represents the burn amount
	// logged by EVM.
	Amount pack.U256 `json:"amount"`

	// Payload is the arbitrary payload of application-specific data that will
	// be constrained by the minting signature.
	Payload pack.Bytes `json:"payload"`
	// Phash is the hash of the payload.
	Phash pack.Bytes32 `json:"phash"`

	// To address that will receive the newly minted pegged assets. This address
	// is the only address that is allowed to submitted the minting signature to
	// the gateway contract.
	To pack.String `json:"to"`

	// Nonce is used to enforce uniqueness. For UTXO-based lock-and-mint
	// transactions, it is used to make unique gateway addresses when all other
	// information is the same. For token-based lock-and-mint transactions, it
	// is used to specify the log index. For burn-and-release and burn-and-mint
	// transactions, it is the nonce emitted by the gateway contract. In all
	// other cases, it must be zero.
	Nonce pack.Bytes32 `json:"nonce"`
	// Nhash is the hash of the underyling transaction details.
	Nhash pack.Bytes32 `json:"nhash"`

	// Gpubkey is the compressed serialisation of the pubkey that identifies the
	// shard into which assets are being locked. For token-based locks, and burn
	// transactions, the gpubkey is expected to be empty.
	Gpubkey pack.Bytes `json:"gpubkey"`
	// Ghash is the gateway hash. It is the hash of the transaction selector,
	// the payload hash, the to address, and the nonce.
	Ghash pack.Bytes32 `json:"ghash"`
}

func NewTxHash(version pack.String, selector pack.String, input pack.Typed) (id.Hash, error) {
	buf := make([]byte, surge.SizeHintString(string(version))+surge.SizeHintString(string(selector))+surge.SizeHint(input))
	return NewTxHashIntoBuffer(version, selector, input, buf)
}

// NewTxHashIntoBuffer write the transaction hash for a transaction with the
// given recipient and inputs into a bytes buffer. An error is returned when the
// recipient and inputs is too large and cannot be marshaled into bytes without
// exceeding memory allocation restrictions. This function is useful when doing
// a lot of hashing, because it allows for buffer re-use.
func NewTxHashIntoBuffer(version pack.String, selector pack.String, input pack.Typed, data []byte) (id.Hash, error) {
	var err error
	buf := data
	rem := surge.MaxBytes
	if buf, rem, err = version.Marshal(buf, rem); err != nil {
		return id.Hash{}, err
	}
	if buf, rem, err = selector.Marshal(buf, rem); err != nil {
		return id.Hash{}, err
	}
	if buf, rem, err = input.Marshal(buf, rem); err != nil {
		return id.Hash{}, err
	}
	return id.NewHash(data), nil
}
