// Independent check #1 (@ton/ton + @ton/core + @ton/crypto + bip39 + ed25519-hd-key).
// wallet "w5" (default), Tonkeeper import logic: phrase valid as TON standard -> TON key, else valid BIP39 ->
//   m/44'/607'/0'; address of W5 (v5r1) mainnet subwallet 0.
// wallet "tg", the wallet built into Telegram, for a 12-word phrase: BIP39 m/44'/607'/0'; address of WalletTg:
//   official trampoline code + storage (revision 0, seqno 0, subwalletId 0x7FFF7F11, public key).
// stdin: JSON lines {"words": "...", "wallet": "w5" | "tg"}; stdout: JSON lines {uq, eq, pub, as, tonValid, bip39Valid}
import { createInterface } from "node:readline";
import { beginCell, Cell, contractAddress } from "@ton/core";
import { mnemonicToPrivateKey, mnemonicValidate } from "@ton/crypto";
import { WalletContractV5R1 } from "@ton/ton";
import { mnemonicToSeedSync, validateMnemonic } from "bip39";
import { derivePath } from "ed25519-hd-key";
import nacl from "tweetnacl";

// github.com/ton-blockchain/tg-wallet-contract, contracts/WalletTrampoline.boc
const TG_TRAMPOLINE = Cell.fromBoc(Buffer.from("b5ee9c7241010101001a000030ff00209821d7498308b9f240df8085f833d0ed1e20ed53d969427e39", "hex"))[0];
const bip39Key = (words) => {
  const { key } = derivePath("m/44'/607'/0'", mnemonicToSeedSync(words.join(" ")).toString("hex"));
  return Buffer.from(nacl.sign.keyPair.fromSeed(key).publicKey);
};

for await (const line of createInterface({ input: process.stdin })) {
  if (!line.trim()) continue;
  const req = JSON.parse(line);
  const words = req.words.trim().split(/\s+/);
  const tonValid = await mnemonicValidate(words);
  const bip39Valid = validateMnemonic(words.join(" "));
  if (req.wallet === "tg") {
    if (!bip39Valid || words.length !== 12) { console.log(JSON.stringify({ error: "not a 12-word BIP39 phrase" })); continue; }
    const pub = bip39Key(words);
    const data = beginCell().storeUint(0, 8).storeUint(0, 32).storeUint(0x7FFF7F11, 32).storeBuffer(pub).endCell();
    const a = contractAddress(0, { code: TG_TRAMPOLINE, data });
    console.log(JSON.stringify({ uq: a.toString({ bounceable: false }), eq: a.toString({ bounceable: true }), pub: pub.toString("hex"), as: "bip39", tonValid, bip39Valid }));
    continue;
  }
  let pub, as;
  if (tonValid) {
    pub = (await mnemonicToPrivateKey(words)).publicKey; as = "ton";
  } else if (bip39Valid) {
    pub = bip39Key(words); as = "bip39";
  } else {
    console.log(JSON.stringify({ error: "invalid phrase" })); continue;
  }
  const w = WalletContractV5R1.create({ publicKey: pub, walletId: { networkGlobalId: -239, context: { walletVersion: "v5r1", workchain: 0, subwalletNumber: 0 } } });
  console.log(JSON.stringify({ uq: w.address.toString({ bounceable: false }), eq: w.address.toString({ bounceable: true }), pub: pub.toString("hex"), as, tonValid, bip39Valid }));
}
