/**
 * Finding Triage Module
 *
 * Layer 1 (feature extraction) of the hybrid triage model.
 * Future layers: CodeBERT embeddings, cross-attention fusion, structured LLM verify.
 */

export { extractFeatures, FEATURE_NAMES } from "./feature-extractor.js";
export { isHoldingItWrong } from "./holding-it-wrong.js";
export type { HoldingItWrongResult } from "./holding-it-wrong.js";
export {
  verifySqli,
  verifyReflectedXss,
  verifySsrf,
  verifyRce,
  verifyPathTraversal,
  verifyIdor,
  verifyOracleByCategory,
  parseRequest,
} from "./oracles.js";
export type { OracleResult } from "./oracles.js";
