// @guenora/draw-engine
// ============================================================================
// Moteur de tirage GUENORA - module PUR, source de vérité unique.
//   - Importé par supabase/functions/execute-draw (serveur) ;
//   - Publié tel quel en open-source (vérification par n'importe qui).
// Si serveur et public exécutent CE module, ils ne peuvent pas diverger (E2).
//
// Conforme à ADR-026 v3 (Annexe A) + ADR-016 + ADR-025 :
//   - SHA-256 uniquement (Web Crypto `crypto.subtle`, dispo Deno/Node18+/navigateur).
//   - proof_hash = SHA-256(nist | btc | tickets_file_hash | closing) — UN SEUL
//     artefact public, l'urne (v3 : participants_file_hash retiré, participants ≡ urne).
//   - rang_brut = int(SHA-256(proof_hash | ticket_hash))  (F7, sur ticket_hash)
//   - tri rang_brut ASC, départage ticket_hash lexicographique ASC
//   - skip logic : 1 récompense max par participant_hash (F3, champ public)
//   - MAX_RANK = 1000 (F10)
// Aucune dépendance.
// ============================================================================

export const MAX_RANK = 1000;

export type DrawOutcome = "main_winner" | "palier_winner" | "skipped" | "not_drawn";

/** Une entrée de l'urne publique : `ticket_hash:participant_hash`. */
export interface UrnEntry {
  ticketHash: string; // 64 hex minuscules
  participantHash: string; // 64 hex minuscules
}

export interface TicketResult extends UrnEntry {
  rangBrut: bigint;
  drawPosition: number; // 1..N, ordre du tri
  outcome: DrawOutcome;
  rewardRank: number | null; // 1..MAX_RANK pour main/palier, null sinon
}

const HEX64 = /^[0-9a-f]{64}$/;

function assertHex64(value: string, label: string): void {
  if (!HEX64.test(value)) {
    throw new Error(`draw-engine: ${label} invalide (attendu 64 hex minuscules) : "${value}"`);
  }
}

/** Octets → hex minuscule. */
function toHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/** Hex (longueur paire, casse indifférente) → octets. Rejette toute entrée non-hex. */
function hexToBytes(hex: string): Uint8Array {
  const h = hex.toLowerCase();
  if (h.length % 2 !== 0 || !/^[0-9a-f]*$/.test(h)) {
    throw new Error(`draw-engine: hex invalide (longueur paire + [0-9a-f]) : "${hex}"`);
  }
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(h.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/** SHA-256 d'une chaîne UTF-8 → hex minuscule 64 car. (Annexe A.1). */
export async function sha256Hex(input: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input));
  return toHex(new Uint8Array(digest));
}

/**
 * Construit l'urne canonique (Annexe A.2) : lignes `ticket_hash:participant_hash`
 * triées par ticket_hash ASC, séparées par LF, SANS newline finale.
 */
export function buildUrn(entries: UrnEntry[]): string {
  for (const e of entries) {
    assertHex64(e.ticketHash, "ticket_hash");
    assertHex64(e.participantHash, "participant_hash");
  }
  return [...entries]
    .sort((a, b) => (a.ticketHash < b.ticketHash ? -1 : a.ticketHash > b.ticketHash ? 1 : 0))
    .map((e) => `${e.ticketHash}:${e.participantHash}`)
    .join("\n");
}

/** Parse l'urne canonique. Urne vide ("") → []. Rejette toute ligne mal formée. */
export function parseUrn(content: string): UrnEntry[] {
  if (content === "") return [];
  return content.split("\n").map((line) => {
    const parts = line.split(":");
    if (parts.length !== 2) {
      throw new Error(`draw-engine: ligne d'urne invalide : "${line}"`);
    }
    const [ticketHash, participantHash] = parts;
    assertHex64(ticketHash, "ticket_hash");
    assertHex64(participantHash, "participant_hash");
    return { ticketHash, participantHash };
  });
}

/** tickets_file_hash = SHA-256(contenu_urne) (Annexe A.2). */
export function ticketsFileHash(urnContent: string): Promise<string> {
  return sha256Hex(urnContent);
}

/**
 * proof_hash v4 (ADR-027, Annexe A.4) : engage une LISTE ORDONNÉE de valeurs de
 * sources d'entropie publiques + l'urne de tickets + le timestamp de clôture.
 *
 *   proof_hash = SHA-256( s_1 | s_2 | ... | s_k | tickets_file_hash | closing )
 *
 * Jeu initial = [btc, drand] → SHA-256( btc | drand | tickets_file_hash | closing ).
 * Les valeurs de sources sont normalisées en minuscule, dans l'ORDRE engagé (figé
 * par concours, ADR-027 §2.3.1). Le moteur ne fetch ni ne vérifie aucune source :
 * chaque valeur (hash de bloc Bitcoin, randomness drand) est un INPUT déjà calculé.
 * Séparateur "|" obligatoire (ADR-011, anti glissement de frontière). Figé : changer
 * l'encodage invalide tout tirage.
 *
 * La surcharge @deprecated v3 ({ nist, btc, ... }) est conservée TEMPORAIREMENT
 * pour qu'execute-draw compile tant que PR B ne l'a pas migré vers `sources` ; elle
 * recalcule l'ancien proof_hash v3 (nist | btc | ...) à l'identique. À RETIRER en
 * PR B (execute-draw passera à `{ sources: [btc, drand], ... }`).
 */
export function computeProofHash(params: {
  sources: readonly string[];
  ticketsFileHash: string;
  closing: string; // ISO-8601 UTC sans ms, suffixe Z
}): Promise<string>;
/** @deprecated v3 (nist|btc). Retiré en PR B (ADR-027) - n'utiliser que `sources`. */
export function computeProofHash(params: {
  nist: string;
  btc: string;
  ticketsFileHash: string;
  closing: string;
}): Promise<string>;
export function computeProofHash(params: {
  sources?: readonly string[];
  nist?: string;
  btc?: string;
  ticketsFileHash: string;
  closing: string;
}): Promise<string> {
  const sources =
    params.sources ??
    [params.nist, params.btc].filter((s): s is string => typeof s === "string");
  const input = [
    ...sources.map((s) => s.toLowerCase()),
    params.ticketsFileHash,
    params.closing,
  ].join("|");
  return sha256Hex(input);
}

// ---------------------------------------------------------------------------
// drand / League of Entropy - quicknet (ADR-027)
// ---------------------------------------------------------------------------
// Le moteur ne fetch RIEN et ne vérifie PAS la signature BLS (lourde, hors noyau,
// ADR-027 §4). Ces helpers laissent un vérificateur tiers dériver la valeur drand
// source EXACTEMENT comme le serveur (randomness = SHA-256(signature)) et retrouver
// le round déterministe associé à draw_scheduled_at.

/**
 * Constantes du réseau drand quicknet, épinglées depuis
 * GET https://api.drand.sh/v2/beacons/quicknet/info (vérifiées 2026-06-19).
 * `genesisTime`/`period` servent au calcul du round ; `chainHash`/`publicKey`/
 * `scheme` documentent la chaîne et permettent à un vérificateur avancé de
 * contrôler la signature BLS contre la clé de groupe (hors moteur).
 */
export const DRAND_QUICKNET = {
  beaconId: "quicknet",
  scheme: "bls-unchained-g1-rfc9380",
  genesisTime: 1692803367,
  period: 3,
  chainHash: "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
  publicKey:
    "83cf0f2896adee7eb8b5f01fcad3912212c437e0073e911fb90022d3e760183c8c4b450b6a0a6c3ac6a5776a2d1064510d1fec758c921cc22b0e17e63aaf4bcb5ed66304de9cf809bd274ca73bab4af5a6e9c76a4bc09e76eae8991ef5ece45a",
} as const;

/**
 * Valeur drand canonique d'un round = randomness = SHA-256(OCTETS de la signature
 * BLS). L'API drand v2 ne renvoie que `signature` (hex) ; on dérive nous-mêmes la
 * randomness pour ne dépendre d'aucun champ calculé côté gateway. Le hash porte sur
 * les octets (hex décodé), PAS sur la chaîne hex. (ADR-027 Annexe A ; vérifié ==
 * `randomness` de l'API legacy.) Retourne 64 hex minuscules.
 */
export async function drandRandomness(signatureHex: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", hexToBytes(signatureHex));
  return toHex(new Uint8Array(digest));
}

/**
 * Round drand retenu pour un instant `epochSeconds` (UTC, secondes) : le PREMIER
 * round dont le temps d'émission est >= t (sémantique "à/après", cohérente avec
 * "premier bloc Bitcoin après draw_scheduled_at").
 *
 *   temps_du_round(r) = genesis + (r - 1) * period
 *   round(t) = ceil( (t - genesis) / period ) + 1            (pour t > genesis)
 *
 * Bord : si t tombe PILE sur un temps de round, ce round-là est retenu (le "à").
 * Pour t <= genesis, retourne 1 (round 1, émis à genesis). Arithmétique ENTIÈRE
 * (pas de flottant) → déterministe, reproductible par un tiers.
 *
 * NB : ADR-027 §2.3.2 écrivait `floor((t-genesis)/period)+1` = round COURANT (à/
 * AVANT t). On retient ici "à/après" pour l'alignement avec la règle Bitcoin -
 * micro-décision figée, à valider (cf. description de PR).
 */
export function drandRoundForTime(
  epochSeconds: number,
  genesis: number,
  period: number,
): number {
  if (
    !Number.isInteger(epochSeconds) ||
    !Number.isInteger(genesis) ||
    !Number.isInteger(period) ||
    period <= 0
  ) {
    throw new Error("draw-engine: drandRoundForTime attend des entiers (period > 0)");
  }
  const delta = epochSeconds - genesis;
  if (delta <= 0) return 1;
  // ceil(delta / period) + 1, en arithmétique entière.
  return Math.floor((delta + period - 1) / period) + 1;
}

/** rang_brut(ticket) = int256(SHA-256(proof_hash | ticket_hash)) (Annexe A.5). */
export async function rangBrut(proofHash: string, ticketHash: string): Promise<bigint> {
  return BigInt("0x" + (await sha256Hex(`${proofHash}|${ticketHash}`)));
}

/**
 * Sélection (Annexe A.6 / ADR-016) : tri par rang_brut ASC (départage ticket_hash
 * ASC), skip logic dédupliquée par participant_hash (F3), MAX_RANK = 1000.
 */
export async function assignOutcomes(
  proofHash: string,
  entries: UrnEntry[],
): Promise<TicketResult[]> {
  const withRanks = await Promise.all(
    entries.map(async (e) => ({ ...e, rangBrut: await rangBrut(proofHash, e.ticketHash) })),
  );

  withRanks.sort((a, b) => {
    if (a.rangBrut < b.rangBrut) return -1;
    if (a.rangBrut > b.rangBrut) return 1;
    // Départage : ticket_hash lexicographique ASC (F7, remplace sequence_no).
    return a.ticketHash < b.ticketHash ? -1 : a.ticketHash > b.ticketHash ? 1 : 0;
  });

  const rewarded = new Set<string>();
  let rewardRank = 0;

  return withRanks.map((e, i) => {
    let outcome: DrawOutcome;
    let rr: number | null = null;
    if (rewarded.has(e.participantHash)) {
      outcome = "skipped";
    } else if (rewardRank < MAX_RANK) {
      rewardRank += 1;
      rewarded.add(e.participantHash);
      rr = rewardRank;
      outcome = rewardRank === 1 ? "main_winner" : "palier_winner";
    } else {
      outcome = "not_drawn";
    }
    return {
      ticketHash: e.ticketHash,
      participantHash: e.participantHash,
      rangBrut: e.rangBrut,
      drawPosition: i + 1,
      outcome,
      rewardRank: rr,
    };
  });
}

/**
 * Vérification de haut niveau : depuis l'urne publique + proof_hash, retrouve le
 * gagnant principal. Retourne null si urne vide (aucun gagnant - cf. ADR-026 F8).
 */
export async function findMainWinner(
  proofHash: string,
  urnContent: string,
): Promise<TicketResult | null> {
  const results = await assignOutcomes(proofHash, parseUrn(urnContent));
  return results.find((r) => r.outcome === "main_winner") ?? null;
}
