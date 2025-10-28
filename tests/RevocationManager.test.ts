import { describe, it, expect, beforeEach } from "vitest";
import { stringUtf8CV, uintCV } from "@stacks/transactions";

const ERR_NOT_AUTHORIZED = 300;
const ERR_PROOF_NOT_FOUND = 301;
const ERR_PROOF_ALREADY_REVOKED = 302;
const ERR_INVALID_REASON = 303;
const ERR_ISSUER_MISMATCH = 305;
const ERR_MAX_REVOCATIONS_EXCEEDED = 306;
const ERR_INVALID_PROOF_ID = 307;

interface Revocation {
  proofId: number;
  issuer: string;
  reason: string;
  timestamp: number;
  status: boolean;
}

interface Result<T> {
  ok: boolean;
  value: T;
}

class MockVerificationEngine {
  proofs: Map<number, any> = new Map();
  revoked: Set<number> = new Set();

  getProof(id: number) {
    const p = this.proofs.get(id);
    return p
      ? { ok: true, value: p }
      : { ok: false, value: ERR_PROOF_NOT_FOUND };
  }

  revokeProof(id: number): Result<boolean> {
    if (!this.proofs.has(id)) return { ok: false, value: ERR_INVALID_PROOF_ID };
    this.revoked.add(id);
    return { ok: true, value: true };
  }

  setProof(id: number, proof: any) {
    this.proofs.set(id, proof);
  }
}

class RevocationManagerMock {
  state: {
    nextRevocationId: number;
    maxRevocations: number;
    revocations: Map<number, Revocation>;
    revocationsByProof: Map<number, number>;
  } = {
    nextRevocationId: 0,
    maxRevocations: 10000,
    revocations: new Map(),
    revocationsByProof: new Map(),
  };
  blockHeight: number = 100;
  caller: string = "ST1ISSUER";
  verificationEngine: MockVerificationEngine;

  constructor() {
    this.verificationEngine = new MockVerificationEngine();
    this.reset();
  }

  reset() {
    this.state = {
      nextRevocationId: 0,
      maxRevocations: 10000,
      revocations: new Map(),
      revocationsByProof: new Map(),
    };
    this.blockHeight = 100;
    this.caller = "ST1ISSUER";
    this.verificationEngine = new MockVerificationEngine();
  }

  getVerificationEngine() {
    return this.verificationEngine;
  }

  revokeProof(proofId: number, reason: string): Result<number> {
    if (this.state.nextRevocationId >= this.state.maxRevocations)
      return { ok: false, value: ERR_MAX_REVOCATIONS_EXCEEDED };
    if (this.state.revocationsByProof.has(proofId))
      return { ok: false, value: ERR_PROOF_ALREADY_REVOKED };
    if (!reason || reason.length > 200)
      return { ok: false, value: ERR_INVALID_REASON };

    const result = this.verificationEngine.getProof(proofId);
    if (!result.ok) return { ok: false, value: result.value };
    const proof = result.value;
    if (proof.issuer !== this.caller)
      return { ok: false, value: ERR_ISSUER_MISMATCH };
    if (!proof.status) return { ok: false, value: ERR_PROOF_ALREADY_REVOKED };

    const id = this.state.nextRevocationId;
    const revocation: Revocation = {
      proofId,
      issuer: this.caller,
      reason,
      timestamp: this.blockHeight,
      status: true,
    };
    this.state.revocations.set(id, revocation);
    this.state.revocationsByProof.set(proofId, id);
    this.state.nextRevocationId++;

    const revokeResult = this.verificationEngine.revokeProof(proofId);
    if (!revokeResult.ok) return { ok: false, value: revokeResult.value };

    return { ok: true, value: id };
  }

  getRevocation(id: number): Revocation | undefined {
    return this.state.revocations.get(id);
  }

  getRevocationByProof(proofId: number): number | undefined {
    return this.state.revocationsByProof.get(proofId);
  }

  isProofRevoked(proofId: number): boolean {
    return this.state.revocationsByProof.has(proofId);
  }

  getRevocationCount(): Result<number> {
    return { ok: true, value: this.state.nextRevocationId };
  }
}

describe("RevocationManager", () => {
  let contract: RevocationManagerMock;

  beforeEach(() => {
    contract = new RevocationManagerMock();
    contract.reset();
  });

  it("revokes proof successfully", () => {
    const ve = contract.getVerificationEngine();
    ve.setProof(5, { issuer: "ST1ISSUER", status: true });
    const result = contract.revokeProof(5, "Fraudulent document detected");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(0);
    const revocation = contract.getRevocation(0);
    expect(revocation?.proofId).toBe(5);
    expect(revocation?.reason).toBe("Fraudulent document detected");
    expect(contract.isProofRevoked(5)).toBe(true);
  });

  it("rejects revocation of non-existent proof", () => {
    const result = contract.revokeProof(99, "Invalid");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_PROOF_NOT_FOUND);
  });

  it("rejects duplicate revocation", () => {
    const ve = contract.getVerificationEngine();
    ve.setProof(10, { issuer: "ST1ISSUER", status: true });
    contract.revokeProof(10, "First reason");
    const result = contract.revokeProof(10, "Second reason");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_PROOF_ALREADY_REVOKED);
  });

  it("rejects revocation by non-issuer", () => {
    const ve = contract.getVerificationEngine();
    ve.setProof(7, { issuer: "ST2OTHER", status: true });
    const result = contract.revokeProof(7, "Wrong issuer");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_ISSUER_MISMATCH);
  });

  it("rejects empty reason", () => {
    const ve = contract.getVerificationEngine();
    ve.setProof(8, { issuer: "ST1ISSUER", status: true });
    const result = contract.revokeProof(8, "");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_REASON);
  });

  it("rejects reason too long", () => {
    const ve = contract.getVerificationEngine();
    ve.setProof(9, { issuer: "ST1ISSUER", status: true });
    const longReason = "a".repeat(201);
    const result = contract.revokeProof(9, longReason);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_REASON);
  });

  it("enforces max revocations", () => {
    contract.state.maxRevocations = 1;
    const ve = contract.getVerificationEngine();
    ve.setProof(1, { issuer: "ST1ISSUER", status: true });
    ve.setProof(2, { issuer: "ST1ISSUER", status: true });
    contract.revokeProof(1, "Limit test");
    const result = contract.revokeProof(2, "Should fail");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_MAX_REVOCATIONS_EXCEEDED);
  });

  it("returns correct revocation count", () => {
    const ve = contract.getVerificationEngine();
    ve.setProof(20, { issuer: "ST1ISSUER", status: true });
    ve.setProof(21, { issuer: "ST1ISSUER", status: true });
    contract.revokeProof(20, "Test 1");
    contract.revokeProof(21, "Test 2");
    const result = contract.getRevocationCount();
    expect(result.ok).toBe(true);
    expect(result.value).toBe(2);
  });

  it("links revocation to proof correctly", () => {
    const ve = contract.getVerificationEngine();
    ve.setProof(15, { issuer: "ST1ISSUER", status: true });
    contract.revokeProof(15, "Linked test");
    const revId = contract.getRevocationByProof(15);
    expect(revId).toBe(0);
    const revocation = contract.getRevocation(0);
    expect(revocation?.proofId).toBe(15);
  });
});
