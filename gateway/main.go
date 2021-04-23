package main

import (
	"io/ioutil"
	"log"

	"go.uber.org/zap"
	"golang.org/x/crypto/ssh"
)

func readKeys() (map[string]bool, error) {
	// Public key authentication is done by comparing
	// the public key of a received connection
	// with the entries in the authorized_keys file.
	authorizedKeysBytes, err := ioutil.ReadFile("authorized_keys")
	if err != nil {
		//return nil, err
	}

	authorizedKeysMap := map[string]bool{}
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			return authorizedKeysMap, err
		}

		authorizedKeysMap[string(pubKey.Marshal())] = true
		authorizedKeysBytes = rest
	}

	return authorizedKeysMap, nil
}

type localForwardChannelData struct {
	DestAddr string
	DestPort uint32

	OriginAddr string
	OriginPort uint32
}

// TODO custom zap core logger that can send logs over the channel
// TODO
func main() {
	pl, _ := zap.NewDevelopment()
	logger := pl.Sugar()
	defer logger.Sync()

	_, err := readKeys()
	if err != nil {
		logger.Fatal("Failed reading keys", "error")
	}

	logger.Info("Creating ssh server")

	s, err := NewServer(logger)
	if err != nil {
		log.Fatal(err)
	}
	logger.Info("Server ready")
	_, err = s.Listen("0.0.0.0:8022")
	if err != nil {
		logger.Error(err.Error())
	}
}
