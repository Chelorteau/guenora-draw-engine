import { defineConfig } from "vitest/config";

// Config autonome : le repo public ne contient QUE ce dossier. On ne dépend
// d'aucune config racine du monorepo. `vitest run` ici exécute uniquement les
// vecteurs canoniques de src/ (ADR-026 Annexe A.7).
export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts"],
  },
});
