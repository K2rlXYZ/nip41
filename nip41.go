package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/nbd-wtf/go-nostr"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

const KEY_CHAIN_LENGTH = 256

func GenerateSeedWords() (string, error) {
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		return "", err
	}

	words, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return "", err
	}

	return words, nil
}

// Get the root from a mnemonic
func getRootFromMnemonic(mnemonic string) (*bip32.Key, error) {
	// Check that the mnemonic is usable as a seed
	if _, err := bip39.EntropyFromMnemonic(mnemonic); err != nil {
		return nil, err
	}

	// Make a seed from the mnemonic
	seed := bip39.NewSeed(mnemonic, "")

	// Make the root from the seed
	key, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, err
	}

	return key, nil
}

// If the key is longer than 64 characters splice it until it is 64
func cropKey(key string) string {
	for len(key) > 64 {
		key = key[1:]
	}

	return key
}

// Get the hidden child secret key at a given index from a root
func getChildSecKeyAtIndex(index uint32, root *bip32.Key) (string, error) {
	// Make a derivation path for the child key from the index
	derivationPath := []uint32{
		bip32.FirstHardenedChild + 44,
		bip32.FirstHardenedChild + 1237,
		bip32.FirstHardenedChild + index,
		0,
		0,
	}

	// Use the root to genereate a child key
	next := root
	for _, id := range derivationPath {
		var err error
		next, err = next.NewChildKey(id)
		if err != nil {
			return "", err
		}
	}

	return hex.EncodeToString(next.Key), nil
}

// Get non hidden secret key from hidden root sk and hidden child sk
func getSecKey(rootSecKey string, childSecKey string) (string, error) {
	bytesRootSecKey, err := hex.DecodeString(rootSecKey)
	if err != nil {
		return "", err
	}

	bytesChildSecKey, err := hex.DecodeString(childSecKey)
	if err != nil {
		return "", err
	}

	// Get the public keys for the non hidden root key and its child key
	pubKeyRoot := secp256k1.PrivKeyFromBytes(bytesRootSecKey).PubKey().SerializeCompressed()[1:]
	pubKeyChild := secp256k1.PrivKeyFromBytes(bytesChildSecKey).PubKey().SerializeCompressed()[1:]

	fmt.Println("gsk pkr", hex.EncodeToString(pubKeyRoot))
	fmt.Println("gsk pkc", hex.EncodeToString(pubKeyChild))

	// Hash sum, hash = sha256(pk(i-1)x' || pk(i)x')
	hash := sha256.Sum256(append(pubKeyRoot, pubKeyChild...))
	hashBig := new(big.Int).SetBytes(hash[:])

	// Add the hash sum to the secret key i (Hidden),  ski = ski' + hash
	var secKeyBig big.Int
	secKeyChildBig := new(big.Int).SetBytes(bytesChildSecKey)
	secKeyBig.Add(secKeyChildBig, hashBig)

	return hex.EncodeToString(secKeyBig.Bytes()), nil
}

// Get the non hidden secret key at the given index for use
func GetSecKeyAtIndex(index uint32, mnemonic string) (string, error) {
	// Get the root object
	root, err := getRootFromMnemonic(mnemonic)
	if err != nil {
		return "", err
	}

	// Get the root secret key from the root object
	rootSecKey := hex.EncodeToString(root.Key)
	if index == 0 {
		return rootSecKey, nil
	}
	var nonHiddenSecKey string

	// Iterate through the indexes to get a secret key for use
	for x := uint32(1); x <= index; x++ {
		// Get the hidden child secret key at index x
		childSecKey, err := getChildSecKeyAtIndex(x, root)
		if err != nil {
			return "", err
		}

		// Get the non hidden secret key from the last secret key (non hidden parent key) and the child secret key at the current index
		nonHiddenSecKey, err = getSecKey(nonHiddenSecKey, childSecKey)
		if err != nil {
			return "", err
		}

		// Crop the key to length 64
		nonHiddenSecKey = cropKey(nonHiddenSecKey)
	}

	return nonHiddenSecKey, nil
}

// Get the index of a given non hidden secret key
func GetSecKeyIndex(sk string, mnemonic string, maxLength uint32) (uint32, error) {
	// Get the root object
	root, err := getRootFromMnemonic(mnemonic)
	if err != nil {
		return 0, err
	}

	// Get the root secret key from the root object
	rootSecKey := hex.EncodeToString(root.Key)
	if sk == rootSecKey {
		return 0, nil
	}
	nonHiddenSecKey := rootSecKey

	for x := uint32(1); x <= maxLength; x++ {
		// Get the hidden child secret key at index x
		childSecKey, err := getChildSecKeyAtIndex(x, root)
		if err != nil {
			return 0, err
		}

		// Get the non hidden secret key from the last secret key (non hidden parent key) and the child secret key at the current index
		nonHiddenSecKey, err = getSecKey(nonHiddenSecKey, childSecKey)
		if err != nil {
			return 0, err
		}

		// Crop the key to length 64
		nonHiddenSecKey = cropKey(nonHiddenSecKey)

		if nonHiddenSecKey == sk {
			return x, nil
		}
	}

	errStr := fmt.Sprintf("Secret key not in this chain of length %v", maxLength+1)
	return 0, errors.New(errStr)
}

// Get the non hidden public key
func GetPubKeyAtIndex(index uint32, mnemonic string) (string, error) {
	sk, err := GetSecKeyAtIndex(index, mnemonic)
	if err != nil {
		return "", err
	}

	skBytes, err := hex.DecodeString(sk)
	if err != nil {
		return "", err
	}

	pk := secp256k1.PrivKeyFromBytes(skBytes).PubKey().SerializeCompressed()[1:]
	return hex.EncodeToString(pk), nil
}

// Get the index of a given non hidden public key
func GetPubKeyIndex(pubKey string, mnemonic string, maxLength uint32) (uint32, error) {
	// Get the root object
	root, err := getRootFromMnemonic(mnemonic)
	if err != nil {
		return 0, err
	}

	// Get the root secret key from the root object
	currentSecKey := hex.EncodeToString(root.Key)

	skBytes, err := hex.DecodeString(currentSecKey)
	if err != nil {
		return 0, err
	}

	// Get the public key from the root secret key
	pkc := hex.EncodeToString(secp256k1.PrivKeyFromBytes(skBytes).PubKey().SerializeCompressed()[1:])

	if pubKey == pkc {
		return 0, nil
	}

	for x := uint32(1); x <= maxLength; x++ {
		// Get the hidden child secret key at index x
		childSecKey, err := getChildSecKeyAtIndex(x, root)
		if err != nil {
			return 0, err
		}

		// Get the non hidden secret key from the last secret key (non hidden parent key) and the child secret key at the current index
		currentSecKey, err = getSecKey(currentSecKey, childSecKey)
		if err != nil {
			return 0, err
		}

		skBytes, err := hex.DecodeString(currentSecKey)
		if err != nil {
			return 0, err
		}

		// Get the public key from the root secret key
		pkc := hex.EncodeToString(secp256k1.PrivKeyFromBytes(skBytes).PubKey().SerializeCompressed()[1:])

		if pubKey == pkc {
			return x, nil
		}
	}

	errStr := fmt.Sprintf("Public key not in this chain of length %v", maxLength+1)
	return 0, errors.New(errStr)
}

func BuildRevocationEventFromPubKey(compromisedPubKey, mnemonic, content string) (string, nostr.Event, error) {
	// Get the index of the compromised public key
	index, err := GetPubKeyIndex(compromisedPubKey, mnemonic, KEY_CHAIN_LENGTH)
	if err != nil {
		return "", nostr.Event{}, err
	}

	ev := nostr.Event{}
	// Get the public key of the account that the event will be posted from
	ev.PubKey, err = GetPubKeyAtIndex(index-1, mnemonic)
	ev.CreatedAt = nostr.Now()
	// Revocation event
	ev.Kind = 13

	// Make the "p" tag ["p", "compromised key"]
	tag1 := append(append(nostr.Tag{}, "p"), compromisedPubKey)

	// Get the root object
	root, err := getRootFromMnemonic(mnemonic)
	if err != nil {
		return "", nostr.Event{}, err
	}

	// Get the hidden secret key at the same index as the compromised key
	hiddenKey, err := getChildSecKeyAtIndex(index, root)
	if err != nil {
		return "", nostr.Event{}, err
	}

	skBytes, err := hex.DecodeString(hiddenKey)
	if err != nil {
		return "", nostr.Event{}, err
	}

	// Get the public key of the hidden key
	pkc := hex.EncodeToString(secp256k1.PrivKeyFromBytes(skBytes).PubKey().SerializeCompressed()[1:])
	// Make the "hidden-key" tag ["hidden-key", "hidden public key of the compromised key"]
	tag2 := append(append(nostr.Tag{}, "hidden-key"), pkc)

	tags := nostr.Tags{tag1, tag2}
	ev.Tags = tags

	ev.Content = content

	// Get the secret key of the account the event will be posted from
	secKey, err := GetSecKeyAtIndex(index+1, mnemonic)
	if err != nil {
		return "", nostr.Event{}, err
	}

	ev.Sign(secKey)

	nextSecKey, err := GetSecKeyAtIndex(index, mnemonic)
	if err != nil {
		return "", nostr.Event{}, err
	}

	return nextSecKey, ev, nil
}

func ValidateRevocationEvent(revEvent nostr.Event, mnemonic string) (bool, error) {
	if revEvent.Kind != 13 {
		return false, nil
	}

	sigGood, err := revEvent.CheckSignature()
	if err != nil {
		return false, err
	}
	if !sigGood {
		return false, nil
	}

	pTagIsntInEv := true
	for x := 0; x < len(revEvent.Tags); x++ {
		for y := 0; x < len(revEvent.Tags[x]); y++ {
			if revEvent.Tags[x][y] == "p" {
				pTagIsntInEv = false
			}
		}
	}
	if pTagIsntInEv {
		return false, nil
	}

	hkTagIsntInEv := true
	var hiddenPubKey string
	for x := 0; x < len(revEvent.Tags); x++ {
		for y := 0; x < len(revEvent.Tags[x]); y++ {
			if revEvent.Tags[x][y] == "hidden-key" {
				hkTagIsntInEv = false
				hiddenPubKey = revEvent.Tags[x][y+1]
			}
		}
	}
	if hkTagIsntInEv {
		return false, nil
	}

	if len(hiddenPubKey) != 33 {
		return false, nil
	}

	//indexInvalidKey, err := GetPubKeyIndex(hiddenPubKey, mnemonic, KEY_CHAIN_LENGTH)

	return true, nil
}
