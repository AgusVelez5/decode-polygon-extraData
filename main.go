package main

import (
	"encoding/json"
	"os"
	"fmt"
	"log"
	"strings"
	"github.com/0xPolygon/polygon-edge/crypto"
	"github.com/0xPolygon/polygon-edge/helper/hex"
	"github.com/0xPolygon/polygon-edge/types"
	"github.com/umbracle/fastrlp"
)

var (
	// IstanbulDigest represents a hash of "Istanbul practical byzantine fault tolerance"
	// to identify whether the block is from Istanbul consensus engine
	IstanbulDigest = types.StringToHash("0x63746963616c2062797a616e74696e65206661756c7420746f6c6572616e6365")

	// IstanbulExtraVanity represents a fixed number of extra-data bytes reserved for proposer vanity
	IstanbulExtraVanity = 32

	// IstanbulExtraSeal represents the fixed number of extra-data bytes reserved for proposer seal
	IstanbulExtraSeal = 65
)

// See https://wiki.polygon.technology/docs/edge/architecture/modules/consensus#extradata
type IstanbulExtra struct {
	Validators    []types.Address
	Seal          []byte
	CommittedSeal [][]byte
}

func stringToBytes(str string) []byte {
	str = strings.TrimPrefix(str, "0x")
	if len(str)%2 == 1 {
		str = "0" + str
	}

	b, _ := hex.DecodeString(str)

	return b
}

// UnmarshalRLPFrom defines the unmarshal implementation for IstanbulExtra
func (i *IstanbulExtra) UnmarshalRLPFrom(p *fastrlp.Parser, v *fastrlp.Value) error {
	elems, err := v.GetElems()
	if err != nil {
		return err
	}

	if len(elems) < 3 {
		return fmt.Errorf("incorrect number of elements to decode istambul extra, expected 3 but found %d", len(elems))
	}
	
	// Seal
	{
		i.Seal, err = elems[1].GetBytes(i.Seal)
		if err != nil {
			return err
		}
	}

	return nil
}

// UnmarshalRLP defines the unmarshal function wrapper for IstanbulExtra
func (i *IstanbulExtra) UnmarshalRLP(input []byte) error {
	return types.UnmarshalRlp(i.UnmarshalRLPFrom, input)
}

func getIbftExtra(h *types.Header) (*IstanbulExtra, error) {
	if len(h.ExtraData) < IstanbulExtraVanity {
		return nil, fmt.Errorf("wrong extra size: %d", len(h.ExtraData))
	}
	
	data := h.ExtraData[IstanbulExtraVanity:]
	
	extra := &IstanbulExtra{}
	if err := extra.UnmarshalRLP(data); err != nil {
		return nil, err
	}

	return extra, nil
}

func ecrecoverImpl(sig, msg []byte) (types.Address, error) {
	pub, err := crypto.RecoverPubkey(sig, crypto.Keccak256(msg))
	if err != nil {
		fmt.Println("error in recover public key")
		return types.Address{}, err
	}

	return crypto.PubKeyToAddress(pub), nil
}

func ecrecoverFromHeader(h *types.Header, hashed []byte) (types.Address, error) {
	// get the extra part that contains the seal
	extra, err := getIbftExtra(h)
	if err != nil {
		fmt.Println("error in IBFT EXTRA")
		return types.Address{}, err
	}
	
	// get the sig
	return ecrecoverImpl(extra.Seal, hashed)
}

func main() {
	header := &types.Header{}
	var payload map[string]interface{}

	content := []byte(os.Args[1])

	// Now let's unmarshall the data into `payload`
	err := json.Unmarshal(content, &payload)
	if err != nil {
		log.Fatal("Error during Unmarshal(): ", err)
	}

	// Let's print the unmarshalled data!
	hashed := stringToBytes(payload["hash"].(string))
	header.ExtraData = stringToBytes(payload["extraData"].(string))
	
	signer, err := ecrecoverFromHeader(header, hashed)
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(signer)
	}
}
