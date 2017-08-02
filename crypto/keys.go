package crypto

import "encoding/pem"

func ReadKeys(rest []byte) (keys map[string][]byte) {
	keys = make(map[string][]byte)
	for {
		var pemBlock *pem.Block
		pemBlock, rest = pem.Decode(rest)
		if pemBlock == nil {
			return
		}
		keys[pemBlock.Type] = pemBlock.Bytes
	}
}
