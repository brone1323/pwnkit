/**
 * Finding Triage Module
 *
 * Layer 1 (feature extraction) of the hybrid triage model.
 * Future layers: CodeBERT embeddings, cross-attention fusion, structured LLM verify.
 */

export { extractFeatures, FEATURE_NAMES } from "./feature-extractor.js";
export { isHoldingItWrong } from "./holding-it-wrong.js";
export type { HoldingItWrongResult } from "./holding-it-wrong.js";
export { checkReachability, extractSinkLocation } from "./reachability.js";
export type { ReachabilityResult, SinkLocation } from "./reachability.js";
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
export { generatePov, judgePovEvidence } from "./pov-gate.js";
export type { PovResult, PovArtifactType, GeneratePovOptions } from "./pov-gate.js";
export {
  checkMultiModalAgreement,
  fuseTriageSignals,
  parseFoxguardSarif,
  detectFoxguard,
} from "./multi-modal.js";
export type {
  MultiModalResult,
  FoxguardFinding,
  Agreement,
  FusedTriageSignals,
  FusedTriageResult,
  FusedDecision,
} from "./multi-modal.js";
export { MemoryStore, scoreMemory, inferPackage } from "./memories.js";
export type {
  TriageMemory,
  MemoryScope,
  MemoryStoreOptions,
  MemoryDbHandle,
} from "./memories.js";
