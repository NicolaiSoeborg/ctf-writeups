# PostNordpolen I

Et krypto-system hvor AES-CTR mode bruges.

## Solve

Efter et antal krypteringer vil `CODEBOOK.next()` løbe tør og gamle værdier genbruges - altså nonce reuse!

### AES-CTR

I CounterMode benytter man `AES(key, Nonce||Counter++)` til at skabe et pseudorandom stream af bytes, kaldet et _keystream_ ("ks").
Så længe man holder _key_ hemmelig, vil _ks_ kunne bruges som et one-time pad og data krypteres ved at XOR'es med KS.

Hvis _nonce_ ("number used only once") genbruges under samme nøgle, så vil to beskeder blive krypteret med samme keystream, hvilket vil sige hvis man XOR de to ciphertekst sammen får man:

`CT1 ⊕ CT2 => (MSG1 ⊕ KS) ⊕ (MSG2 ⊕ KS) => MSG1 ⊕ MSG2 ⊕ (KS ⊕ KS) => MSG1 ⊕ MSG2 ⊕ \x00 => MSG1 ⊕ MSG2`

Altså de to _KS_ går ud med hinanden og hvis man kender MSG1, kan mange regne MSG2 ud.

Vi benytter dette til at modtage det krypterede flag og derefter kryptere et stort antal beskeder indeholdende "AAA…", når nonce genbruges vil `FLAG_ENC ⊕ ENC(AAA…) ⊕ AAA…` indeholde det dekrypterede flag.

## Flag

Se [solve.py](solve.py)
