package main

var config Config

type Config struct {
	DataDir             string
	Mnemonic            string
	Lock                bool
	CurrentSecKeyNumber uint32
}

func (c *Config) Init() {
}
