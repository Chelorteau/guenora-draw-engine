// @guenora/draw-engine
// ============================================================================
// Moteur de tirage GUENORA - module PUR, source de vérité unique.
//   - Importé par supabase/functions/execute-draw (serveur) ;
//   - Publié tel quel en open-source (vérification par n'importe qui).
// Si serveur et public exécutent CE module, ils ne peuvent pas diverger (E2).
//
// Conforme à ADR-026 v2 (Annexe A) + ADR-016 + ADR-025 :
//   - SHA-256 uniquement (Web Crypto `crypto.subtle`, dispo Deno/Node18+/navigateur).
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

/** SHA-256 d'une chaîne UTF-8 → hex minuscule 64 car. (Annexe A.1). */
export async function sha256Hex(input: string): Promise<string> {
  const bytes = new TextEncoder().encode(input);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
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
 * proof_hash (Annexe A.4) : engage les DEUX fichiers (participants + urne).
 * `nist` et `btc` sont normalisés en minuscule.
 */
export function computeProofHash(params: {
  nist: string;
  btc: string;
  participantsFileHash: string;
  ticketsFileHash: string;
  closing: string; // ISO-8601 UTC sans ms, suffixe Z
}): Promise<string> {
  const input = [
    params.nist.toLowerCase(),
    params.btc.toLowerCase(),
    params.participantsFileHash,
    params.ticketsFileHash,
    params.closing,
  ].join("|");
  return sha256Hex(input);
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
