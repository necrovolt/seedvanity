// Independent check #2 (tonutils-go), same Tonkeeper import logic as verify/w5addr.mjs:
// SeedToPrivateKeyWithOptions(..., WithBIP39(true)) = TON standard if valid, else BIP39 m/44'/607'/0'.
// stdin: JSON lines {"words": "..."}; stdout: JSON lines {uq, eq, pub, as, tonValid, bip39Valid}
package main

import (
	"bufio"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/tyler-smith/go-bip39"
	"github.com/xssnick/tonutils-go/ton/wallet"
)

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var in struct{ Words string }
		if strings.TrimSpace(sc.Text()) == "" {
			continue
		}
		if err := json.Unmarshal(sc.Bytes(), &in); err != nil {
			fmt.Println(`{"error":"bad json"}`)
			continue
		}
		words := strings.Fields(in.Words)
		_, errTon := wallet.SeedToPrivateKeyWithOptions(words)
		tonValid := errTon == nil
		bipValid := bip39.IsMnemonicValid(strings.Join(words, " "))
		k, err := wallet.SeedToPrivateKeyWithOptions(words, wallet.WithBIP39(true))
		if err != nil {
			fmt.Printf("{\"error\":%q}\n", err.Error())
			continue
		}
		w, err := wallet.FromPrivateKey(nil, k, wallet.ConfigV5R1Final{NetworkGlobalID: -239, Workchain: 0})
		if err != nil {
			fmt.Printf("{\"error\":%q}\n", err.Error())
			continue
		}
		a := w.WalletAddress()
		a.SetBounce(false)
		uq := a.String()
		a.SetBounce(true)
		eq := a.String()
		as := "bip39"
		if tonValid {
			as = "ton"
		}
		out, _ := json.Marshal(map[string]any{"uq": uq, "eq": eq, "pub": hex.EncodeToString(k.Public().(ed25519.PublicKey)), "as": as, "tonValid": tonValid, "bip39Valid": bipValid})
		fmt.Println(string(out))
	}
}
