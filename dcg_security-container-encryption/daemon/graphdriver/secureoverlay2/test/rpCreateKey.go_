package main

import (
	"log"
	"github.com/jsipprell/keyctl"
	"flag"
)

// holds command line arguments
//	TimeOut: time out value for session in seconds
//	KeyID: key identifier to read the key after creation
//	Key: key to be used for encryption
type cmdArgs struct {
	TimeOut	uint
	KeyID	string
	Key	string
}

func createKey(timeOut uint, keyID, key string) error {
	keyring, err := keyctl.SessionKeyring()
	if err != nil { return err}

	keyring.SetDefaultTimeout(timeOut)
	secureData := []byte(key)
	id, err := keyring.Add(keyID, secureData)
	if err != nil { return err }

	info, err := id.Info(); if err == nil {
		log.Printf("key info: %v", info)
	}

	return nil
}

func main() {
	// set default value for arguments
	args := cmdArgs{3600, "", ""}

	// define command line arguments
	flag.UintVar(&args.TimeOut, "timeout", 3600, "set time out for session. Key will expire after time out.")
	flag.StringVar(&args.KeyID, "id", "rp-key", "identifier to deal with key in the keyrings")
	flag.StringVar(&args.Key, "key", "", "key to be stored in the keyrings")

	flag.Parse()

	if err := createKey(args.TimeOut, args.KeyID, args.Key); err != nil {
		log.Printf("error in key creation: %s", err.Error())
	} else {
		log.Printf("key successfully created with key id: %s", args.KeyID)
	}
}
