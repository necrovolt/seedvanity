// Independent check #2 (tonutils-go), same logic as verify/w5addr.mjs:
// wallet "w5" (default): SeedToPrivateKeyWithOptions(..., WithBIP39(true)) = TON standard if valid, else BIP39
// m/44'/607'/0'; W5 (v5r1) mainnet subwallet 0. wallet "tg": the Telegram wallet (WalletTg), a 12-word phrase is
// always read as BIP39 m/44'/607'/0'; the official trampoline code + storage (revision 0, seqno 0,
// subwalletId 0x7FFF7F11, public key), built with tonutils-go cells.
// stdin: JSON lines {"words": "...", "wallet": "w5" | "tg"}; stdout: JSON lines {uq, eq, pub, as, tonValid, bip39Valid}
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
	"github.com/xssnick/tonutils-go/address"
	"github.com/xssnick/tonutils-go/tlb"
	"github.com/xssnick/tonutils-go/ton/wallet"
	"github.com/xssnick/tonutils-go/ton/wallet/hdwallet"
	"github.com/xssnick/tonutils-go/tvm/cell"
)

// github.com/ton-blockchain/tg-wallet-contract, contracts/WalletTrampoline.boc
const tgTrampolineBOC = "b5ee9c7241010101001a000030ff00209821d7498308b9f240df8085f833d0ed1e20ed53d969427e39"

func telegramAddress(pub ed25519.PublicKey) (*address.Address, error) {
	boc, _ := hex.DecodeString(tgTrampolineBOC)
	code, err := cell.FromBOC(boc)
	if err != nil {
		return nil, err
	}
	data := cell.BeginCell().MustStoreUInt(0, 8).MustStoreUInt(0, 32).MustStoreUInt(0x7FFF7F11, 32).
		MustStoreSlice(pub, 256).EndCell()
	return tlb.StateInit{Code: code, Data: data}.CalcAddress(0), nil
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		var in struct{ Words, Wallet string }
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
		var a *address.Address
		as := "bip39"
		if in.Wallet == "tg" {
			if len(words) != 12 || !bipValid {
				fmt.Println(`{"error":"not a 12-word BIP39 phrase"}`)
				continue
			}
			dk, derr := hdwallet.Derived("m/44'/607'/0'", bip39.NewSeed(strings.Join(words, " "), ""))
			if derr != nil {
				fmt.Printf("{\"error\":%q}\n", derr.Error())
				continue
			}
			k = ed25519.NewKeyFromSeed(dk.PrivateKey)
			a, err = telegramAddress(k.Public().(ed25519.PublicKey))
		} else {
			if tonValid {
				as = "ton"
			}
			var w *wallet.Wallet
			w, err = wallet.FromPrivateKey(nil, k, wallet.ConfigV5R1Final{NetworkGlobalID: -239, Workchain: 0})
			if err == nil {
				a = w.WalletAddress()
			}
		}
		if err != nil {
			fmt.Printf("{\"error\":%q}\n", err.Error())
			continue
		}
		a.SetBounce(false)
		uq := a.String()
		a.SetBounce(true)
		eq := a.String()
		out, _ := json.Marshal(map[string]any{"uq": uq, "eq": eq, "pub": hex.EncodeToString(k.Public().(ed25519.PublicKey)), "as": as, "tonValid": tonValid, "bip39Valid": bipValid})
		fmt.Println(string(out))
	}
}
