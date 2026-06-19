import { describe, it, expect } from "vitest";
import {
  sha256Hex,
  buildUrn,
  parseUrn,
  ticketsFileHash,
  computeProofHash,
  drandRandomness,
  drandRoundForTime,
  DRAND_QUICKNET,
  rangBrut,
  assignOutcomes,
  findMainWinner,
  MAX_RANK,
} from "./index";

// ============================================================================
// Vecteurs de test canoniques - ADR-026 v2, Annexe A.7.
// Générés par `printf "%s" ... | sha256sum`. Toute divergence = bug d'encodage.
// ============================================================================

const PROOF_HASH = "beef6fbaedcc61da6612be32b4442e92edb7d00b5db9064b0825a38613f990dd";

const T1 = "b4e850149ee45e0f56b21c09c7199f9b005d9b3e308ef4f0e00bb55075200185";
const PH_A = "8fef3361e72c4fefc917680e3ef759828d4d12a4751301d58e9ccd50f2effbe5";
const T2 = "cddd949ecdebf7652181129cbfda1cc9c343c75006fce5b47767c8def5883665";
const PH_B = "17d68caa7c363be8914f1ca34ad12c80074918ad4c551b57c39282c49d9f45a3";

const RANG_1 = BigInt("0xe402734220246f253a61abea1ee8b14aa01a2af5f9041a98f745a409db47d66c");
const RANG_2 = BigInt("0x4ee9726ef69c12d6711bfe2b325a84f8db1b9744ddcdecd2b73f590838fe3cee");

const URN_CONTENT = `${T1}:${PH_A}\n${T2}:${PH_B}`;
const TICKETS_FILE_HASH = "5bdc87890053f8233b572d6a3b399081ea4a70e580eb7f80c7cd363fde65e4c4";

// Sources d'entropie v4 (ADR-027). DRAND_RANDOMNESS = randomness du round drand
// quicknet 20000000 = SHA-256 des OCTETS de sa signature (vecteur réel pinné,
// récupéré le 2026-06-19, vérifié == randomness de l'API legacy).
const BTC = "0000000000000000000abcdef1234567890fedcba0987654321aabbccddeeff0";
const DRAND_RANDOMNESS = "f39c98df5525968e6622e0c63edb3d1f9c5607cf780db78abdded36e4b3dba95";

describe("sha256Hex (A.1)", () => {
  it("reproduit le proof_hash de référence", async () => {
    expect(await sha256Hex("guenora-demo-proof-input")).toBe(PROOF_HASH);
  });
});

describe("buildUrn / parseUrn (A.2)", () => {
  it("trie par ticket_hash ASC, LF, sans newline finale", () => {
    // entrées dans le désordre -> doit ressortir triées (T1 < T2)
    expect(buildUrn([{ ticketHash: T2, participantHash: PH_B }, { ticketHash: T1, participantHash: PH_A }]))
      .toBe(URN_CONTENT);
  });
  it("urne vide -> contenu vide et inversement", () => {
    expect(buildUrn([])).toBe("");
    expect(parseUrn("")).toEqual([]);
  });
  it("round-trip parse(build) === entrées", () => {
    expect(parseUrn(URN_CONTENT)).toEqual([
      { ticketHash: T1, participantHash: PH_A },
      { ticketHash: T2, participantHash: PH_B },
    ]);
  });
  it("rejette une ligne mal formée", () => {
    expect(() => parseUrn("pasunhash:pasunhash")).toThrow();
  });
});

describe("ticketsFileHash (A.2)", () => {
  it("hashe l'urne canonique vers le vecteur de référence", async () => {
    expect(await ticketsFileHash(URN_CONTENT)).toBe(TICKETS_FILE_HASH);
  });
});

describe("computeProofHash (A.4, ADR-027 v4 : liste ordonnée de sources)", () => {
  it("engage s_1|...|s_k|tickets|closing - jeu initial [btc, drand] (vecteur de référence v4)", async () => {
    const proof = await computeProofHash({
      sources: [BTC, DRAND_RANDOMNESS],
      ticketsFileHash: TICKETS_FILE_HASH,
      closing: "2026-06-15T14:00:00Z",
    });
    expect(proof).toBe("e62e6ba16d0e29f21e6981f3b3da2e7a4d6463a65d3e6183bed9bcafe5029181");
  });

  it("normalise les sources en minuscule (casse indifférente)", async () => {
    const lower = await computeProofHash({ sources: ["abc", "def"], ticketsFileHash: "y", closing: "z" });
    const upper = await computeProofHash({ sources: ["ABC", "DEF"], ticketsFileHash: "y", closing: "z" });
    expect(lower).toBe(upper);
  });

  it("l'ordre des sources est engagé : btc|drand != drand|btc", async () => {
    const a = await computeProofHash({ sources: [BTC, DRAND_RANDOMNESS], ticketsFileHash: "y", closing: "z" });
    const b = await computeProofHash({ sources: [DRAND_RANDOMNESS, BTC], ticketsFileHash: "y", closing: "z" });
    expect(a).not.toBe(b);
  });

  it("rétro-compat : surcharge @deprecated {nist,btc} == ancien proof v3 == sources:[nist,btc]", async () => {
    const v3 = await computeProofHash({
      nist: "a1b2c3d4nistbeaconvalue",
      btc: BTC,
      ticketsFileHash: TICKETS_FILE_HASH,
      closing: "2026-06-15T14:00:00Z",
    });
    expect(v3).toBe("83d008158424be67f482687af3d607405cf7da036e29891167c32704baf0dc83");
    const viaSources = await computeProofHash({
      sources: ["a1b2c3d4nistbeaconvalue", BTC],
      ticketsFileHash: TICKETS_FILE_HASH,
      closing: "2026-06-15T14:00:00Z",
    });
    expect(viaSources).toBe(v3);
  });
});

describe("drand quicknet helpers (ADR-027 Annexe A)", () => {
  // Vecteur réel : round 20000000 du beacon quicknet (historique, fixe). Signature
  // récupérée le 2026-06-19 depuis api.drand.sh ; randomness dérivée vérifiée.
  const ROUND_20M_SIG =
    "96892582a33552a7b67ba44ef09c3ccd535bbebe760c93ecf45be8958d0c0f06390c6d19d7bf492eb806af7eef6b125c";

  it("drandRandomness = SHA-256(signature_bytes) (vecteur round 20000000)", async () => {
    expect(await drandRandomness(ROUND_20M_SIG)).toBe(DRAND_RANDOMNESS);
  });

  it("drandRandomness hash les OCTETS, pas la chaîne hex", async () => {
    expect(await drandRandomness(ROUND_20M_SIG)).not.toBe(await sha256Hex(ROUND_20M_SIG));
  });

  it("drandRandomness rejette une signature non-hex", async () => {
    await expect(drandRandomness("xyz")).rejects.toThrow();
  });

  it("constantes quicknet épinglées (genesis/period/chainHash/scheme)", () => {
    expect(DRAND_QUICKNET.genesisTime).toBe(1692803367);
    expect(DRAND_QUICKNET.period).toBe(3);
    expect(DRAND_QUICKNET.chainHash).toBe(
      "52db9ba70e0cc0f6eaf7803dd07447a1f5477735fd3f661792ba94600c84e971",
    );
    expect(DRAND_QUICKNET.scheme).toBe("bls-unchained-g1-rfc9380");
  });

  it("drandRoundForTime : premier round à/après t (bords inclus)", () => {
    const { genesisTime: g, period: p } = DRAND_QUICKNET;
    const timeOfRound20M = g + (20000000 - 1) * p;
    expect(timeOfRound20M).toBe(1752803364);
    expect(drandRoundForTime(timeOfRound20M, g, p)).toBe(20000000); // pile -> ce round (à)
    expect(drandRoundForTime(timeOfRound20M + 1, g, p)).toBe(20000001); // 1s après -> suivant
    expect(drandRoundForTime(timeOfRound20M - 1, g, p)).toBe(20000000); // 1s avant -> à/après
    expect(drandRoundForTime(g, g, p)).toBe(1); // t == genesis -> round 1
    expect(drandRoundForTime(g - 100, g, p)).toBe(1); // t < genesis -> round 1
  });
});

describe("rangBrut (A.5)", () => {
  it("reproduit les rangs de référence", async () => {
    expect(await rangBrut(PROOF_HASH, T1)).toBe(RANG_1);
    expect(await rangBrut(PROOF_HASH, T2)).toBe(RANG_2);
  });
});

describe("assignOutcomes / findMainWinner (A.6)", () => {
  it("le plus petit rang_brut gagne (ticket #2 ici, RANG_2 < RANG_1)", async () => {
    const results = await assignOutcomes(PROOF_HASH, [
      { ticketHash: T1, participantHash: PH_A },
      { ticketHash: T2, participantHash: PH_B },
    ]);
    // tri : #2 d'abord (rang plus petit)
    expect(results[0].ticketHash).toBe(T2);
    expect(results[0].outcome).toBe("main_winner");
    expect(results[0].rewardRank).toBe(1);
    expect(results[1].ticketHash).toBe(T1);
    expect(results[1].outcome).toBe("palier_winner");
    expect(results[1].rewardRank).toBe(2);
  });

  it("findMainWinner renvoie le gagnant depuis l'urne publique", async () => {
    const winner = await findMainWinner(PROOF_HASH, URN_CONTENT);
    expect(winner?.ticketHash).toBe(T2);
    expect(winner?.participantHash).toBe(PH_B);
  });

  it("urne vide -> aucun gagnant", async () => {
    expect(await findMainWinner(PROOF_HASH, "")).toBeNull();
  });

  it("skip logic : un participant n'a qu'une seule récompense (ses autres tickets = skipped)", async () => {
    // PH_A possède 2 tickets ; il ne doit gagner qu'une fois, le 2e -> skipped.
    const results = await assignOutcomes(PROOF_HASH, [
      { ticketHash: T1, participantHash: PH_A },
      { ticketHash: T2, participantHash: PH_A }, // même owner
    ]);
    const rewarded = results.filter((r) => r.outcome === "main_winner" || r.outcome === "palier_winner");
    const skipped = results.filter((r) => r.outcome === "skipped");
    expect(rewarded).toHaveLength(1);
    expect(skipped).toHaveLength(1);
  });
});

describe("constantes", () => {
  it("MAX_RANK = 1000 (F10)", () => {
    expect(MAX_RANK).toBe(1000);
  });
});
