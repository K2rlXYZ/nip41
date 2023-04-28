package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/docopt/docopt-go"
	"github.com/mitchellh/go-homedir"
)

func saveConfig(path string) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC|os.O_CREATE, 0644)
	if err != nil {
		log.Fatal("can't open config file " + path + ": " + err.Error())
		return
	}

	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")

	enc.Encode(config)
}

const USAGE = `
Usage: 
  nip41-cli new-seed
  nip41-cli toggle-lock
  nip41-cli seckey current [--index]
  nip41-cli seckey next [--index]`

func main() {
	// find datadir
	flag.StringVar(&config.DataDir, "datadir", "~/.config/nostr",
		"Base directory for configurations and data from Nostr.")
	flag.Parse()
	config.DataDir, _ = homedir.Expand(config.DataDir)
	os.Mkdir(config.DataDir, 0700)

	// logger config
	log.SetPrefix("<> ")

	// parse config
	path := filepath.Join(config.DataDir, "nip41-cli-config.json")
	f, err := os.Open(path)
	if err != nil {
		config.CurrentSecKeyNumber = 256
		saveConfig(path)
		f, _ = os.Open(path)
	}
	f, _ = os.Open(path)
	err = json.NewDecoder(f).Decode(&config)
	if err != nil {
		log.Fatal("can't parse config file " + path + ": " + err.Error())
		return
	}
	config.Init()

	// parse args
	opts, err := docopt.ParseArgs(USAGE, flag.Args(), "")
	if err != nil {
		log.Println(USAGE)
		return
	}

	switch {
	case opts["new-seed"].(bool):
		if config.Lock != true {
			words, err := GenerateSeedWords()
			if err != nil {
				log.Fatal(err)
				return
			}
			config.Mnemonic = words
			saveConfig(path)
			fmt.Printf("New mnemonic seed set: %v", words)
		} else if config.Lock == true {
			fmt.Println("Mnemonic locked, to change it run toggle-lock and then new-seed")
		}

	case opts["toggle-lock"].(bool):
		config.Lock = !config.Lock
		saveConfig(path)
		if config.Lock == true {
			fmt.Println("Locked the mnemonic, to change it run toggle-lock and then new-seed")
		} else {
			fmt.Println("Unlocked the mnemonic")
		}

	case opts["seckey"].(bool):
		switch {
		case opts["current"].(bool):
			sk, err := GetSecKeyAtIndex(uint32(config.CurrentSecKeyNumber-1), config.Mnemonic)
			if err != nil {
				if err.Error() == "Invalid mnenomic" {
					log.Fatal("Mnemonic not set, set it with new-seed")
				} else {
					log.Fatal()
				}

				return
			}

			fmt.Printf("The current secret key in the chain is: %v", sk)
			index, _ := opts.Bool("--index")
			if index {
				fmt.Println()
				fmt.Printf("It is the %v. key in the chain", uint32(KEY_CHAIN_LENGTH-(config.CurrentSecKeyNumber-1)))
				fmt.Println()
			}

		case opts["next"].(bool):
			sk, err := GetSecKeyAtIndex(uint32(config.CurrentSecKeyNumber-2), config.Mnemonic)
			if err != nil {
				if err.Error() == "Invalid mnenomic" {
					log.Fatal("Mnemonic not set, set it with new-seed")
				} else {
					log.Fatal()
				}

				return
			}

			fmt.Printf("The next secret key in the chain is: %v", sk)
			index, _ := opts.Bool("--index")
			if index {
				fmt.Println()
				fmt.Printf("It is the %v. key in the chain", uint32(KEY_CHAIN_LENGTH-(config.CurrentSecKeyNumber-2)))
				fmt.Println()
			}
		}

	case opts["invalidate"].(bool):

	}
}
