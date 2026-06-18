# @guenora/draw-engine

Moteur de tirage **GUENORA** - sélection du gagnant **vérifiable et reproductible**.

> Source de vérité **unique** : ce module est importé par `supabase/functions/execute-draw`
> (côté serveur) **et** publié en open-source. Serveur et vérificateur exécutant le
> même code, ils ne peuvent pas diverger. C'est le cœur de la promesse "tirage
> certifié, rejouable par n'importe qui" (ADR-026).

## Garanties

- **SHA-256 uniquement** (Web Crypto, fonctionne en Deno / Node 18+ / navigateur).
- **Aucune dépendance.**
- Algorithme figé par l'**annexe d'encodage canonique** (ADR-026 §Annexe A) + **vecteurs de test** (`src/index.test.ts`).

## Algorithme (ADR-016 + ADR-026 v3)

```
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
import { ticketsFileHash, computeProofHash, findMainWinner } from "@guenora/draw-engine";

// 1. Télécharger l'urne publique (format : ticket_hash:participant_hash, triée
//    par ticket_hash) et les valeurs publiées dans `draws`.
const tfh = await ticketsFileHash(urneContent);
// 2. Recomposer proof_hash (ADR-026 v3 : urne seule) et comparer à draws.proof_hash.
const proof = await computeProofHash({
  nist,
  btc,
  ticketsFileHash: tfh,
  closing,
});
// 3. Rejouer la sélection et comparer au gagnant publié.
const winner = await findMainWinner(proof, urneContent);
```

Et vérifier que l'urne était **ancrée avant l'aléa** (OpenTimestamps, cf. `docs/runbooks/ots-ancrage-manuel.md`).

## API

- `sha256Hex(input)` · `buildUrn(entries)` · `parseUrn(content)` · `ticketsFileHash(urn)`
- `computeProofHash({ nist, btc, ticketsFileHash, closing })` (ADR-026 v3 : urne seule)
- `rangBrut(proofHash, ticketHash)` · `assignOutcomes(proofHash, entries)` · `findMainWinner(proofHash, urn)`
- `MAX_RANK`

## Tests

```bash
npm test        # vitest : vecteurs canoniques (ADR-026 §Annexe A.7)
```
