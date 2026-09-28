// Independent check #1 (@ton/ton + @ton/crypto + bip39 + ed25519-hd-key), Tonkeeper import logic:
// phrase valid as TON standard -> TON key, else valid BIP39 -> m/44'/607'/0'. Then W5 (v5r1) mainnet subwallet 0.
// stdin: JSON lines {"words": "..."}; stdout: JSON lines {uq, eq, pub, as, tonValid, bip39Valid}
import { createInterface } from "node:readline";
import { mnemonicToPrivateKey, mnemonicValidate } from "@ton/crypto";
import { WalletContractV5R1 } from "@ton/ton";
import { mnemonicToSeedSync, validateMnemonic } from "bip39";
import { derivePath } from "ed25519-hd-key";
import nacl from "tweetnacl";

for await (const line of createInterface({ input: process.stdin })) {
  if (!line.trim()) continue;
  const words = JSON.parse(line).words.trim().split(/\s+/);
  const tonValid = await mnemonicValidate(words);
  const bip39Valid = validateMnemonic(words.join(" "));
  let pub, as;
  if (tonValid) {
    pub = (await mnemonicToPrivateKey(words)).publicKey; as = "ton";
  } else if (bip39Valid) {
    const { key } = derivePath("m/44'/607'/0'", mnemonicToSeedSync(words.join(" ")).toString("hex"));
    pub = Buffer.from(nacl.sign.keyPair.fromSeed(key).publicKey); as = "bip39";
  } else {
    console.log(JSON.stringify({ error: "invalid phrase" })); continue;
  }
  const w = WalletContractV5R1.create({ publicKey: pub, walletId: { networkGlobalId: -239, context: { walletVersion: "v5r1", workchain: 0, subwalletNumber: 0 } } });
  console.log(JSON.stringify({ uq: w.address.toString({ bounceable: false }), eq: w.address.toString({ bounceable: true }), pub: pub.toString("hex"), as, tonValid, bip39Valid }));
}
