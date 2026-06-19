# @guenora/draw-engine

> **Miroir en lecture seule** du dossier `packages/draw-engine` du monorepo GUENORA.
> Le développement se fait en amont ; n'ouvrez pas de PR ici.

Moteur de tirage **GUENORA** - sélection du gagnant **vérifiable et reproductible**.

> Source de vérité **unique** : ce module est importé par `supabase/functions/execute-draw`
> (côté serveur) **et** publié en open-source. Serveur et vérificateur exécutant le
> même code, ils ne peuvent pas diverger. C'est le cœur de la promesse "tirage
> certifié, rejouable par n'importe qui" (ADR-026).

## Garanties

- **SHA-256 uniquement** (Web Crypto, fonctionne en Deno / Node 18+ / navigateur).
- **Aucune dépendance.**
- Algorithme figé par l'**annexe d'encodage canonique** (ADR-026 §Annexe A + ADR-027 §Annexe B pour la v4) + **vecteurs de test** (`src/index.test.ts`).

## Algorithme (ADR-016 + ADR-026 + ADR-027 v4)

```
proof_hash = SHA-256( s_1 | s_2 | ... | s_k | tickets_file_hash | closing )   # ADR-027 v4
  jeu de sources initial = [ btc, drand ] : SHA-256( btc | drand | tickets_file_hash | closing )
  sources en minuscule, dans l'ordre engagé (figé par concours, ADR-027 §2.3.1)

rang_brut(ticket) = int256( SHA-256( proof_hash | ticket_hash ) )      # F7 : sur ticket_hash
tri par rang_brut ASC, départage ticket_hash lexicographique ASC
skip logic : 1 récompense max par participant_hash (champ public)       # F3
  - 1er owner non récompensé        -> main_winner   (reward_rank 1)
  - owners suivants jusqu'à MAX_RANK -> palier_winner (reward_rank 2..1000)
  - owner déjà récompensé           -> skipped
  - au-delà de MAX_RANK             -> not_drawn
MAX_RANK = 1000
```

## Vérifier un tirage (tiers, données publiques uniquement)

```ts
import {
  ticketsFileHash,
  computeProofHash,
  findMainWinner,
  drandRandomness,
  drandRoundForTime,
  DRAND_QUICKNET,
} from "@guenora/draw-engine";

// 1. Télécharger l'urne publique (ticket_hash:participant_hash, triée par
//    ticket_hash) + les valeurs publiées dans `draws` (sources engagées, closing).
const tfh = await ticketsFileHash(urneContent);

// 2. Dériver soi-même chaque valeur de source (sans faire confiance à GUENORA) :
//    - btc   = hash du 1er bloc Bitcoin après draw_scheduled_at (via un explorateur)
//    - drand : round = drandRoundForTime(drawScheduledEpoch, DRAND_QUICKNET.genesisTime,
//              DRAND_QUICKNET.period) ; fetch sa signature sur api.drand.sh ;
//              const drand = await drandRandomness(signatureHex)
// 3. Recomposer proof_hash v4 (ADR-027 : liste ordonnée de sources) et comparer.
const proof = await computeProofHash({
  sources: [btc, drand], // ordre engagé, figé par concours
  ticketsFileHash: tfh,
  closing,
});
// 4. Rejouer la sélection et comparer au gagnant publié.
const winner = await findMainWinner(proof, urneContent);
```

Et vérifier que l'urne était **ancrée avant l'aléa** via OpenTimestamps (la procédure
d'ancrage manuel est documentée dans le runbook interne du monorepo GUENORA, en amont).

## API

- `sha256Hex(input)` · `buildUrn(entries)` · `parseUrn(content)` · `ticketsFileHash(urn)`
- `computeProofHash({ sources, ticketsFileHash, closing })` (ADR-027 v4 : liste ordonnée de sources)
  - surcharge `@deprecated` `{ nist, btc, ticketsFileHash, closing }` (v3) - retirée en PR B
- `drandRandomness(signatureHex)` · `drandRoundForTime(epochSeconds, genesis, period)` · `DRAND_QUICKNET`
- `rangBrut(proofHash, ticketHash)` · `assignOutcomes(proofHash, entries)` · `findMainWinner(proofHash, urn)`
- `MAX_RANK`

## Tests

```bash
npm install     # vitest + typescript (devDependencies autonomes)
npm test        # vitest : vecteurs canoniques (ADR-026 §A + ADR-027 §B v4 + drand)
```

## Licence

[MIT](./LICENSE) - Copyright (c) 2026 Chelo Lorteau / GUENORA.
