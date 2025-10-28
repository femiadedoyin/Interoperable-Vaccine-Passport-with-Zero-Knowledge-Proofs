import { describe, it, expect, beforeEach } from "vitest";
import { buffCV, uintCV } from "@stacks/transactions";

const ERR_NOT_AUTHORIZED = 100;
const ERR_INVALID_PROOF = 101;
const ERR_INVALID_VK = 102;
const ERR_INVALID_PUBLIC_INPUT = 103;
const ERR_PROOF_ALREADY_USED = 104;
const ERR_ISSUER_NOT_REGISTERED = 105;
const ERR_INVALID_TIMESTAMP = 107;
const ERR_VERIFICATION_FAILED = 108;
const ERR_INVALID_CHALLENGE = 109;
const ERR_INVALID_PROOF_LENGTH = 110;
const ERR_INVALID_VK_PARAMS = 111;
const ERR_INVALID_STATUS = 112;
const ERR_INVALID_EXPIRY = 113;
const ERR_PROOF_EXPIRED = 114;
const ERR_INVALID_VACCINE_TYPE = 115;
const ERR_INVALID_DOSE_COUNT = 116;
const ERR_INVALID_ISSUER_SIG = 117;
const ERR_MAX_PROOFS_EXCEEDED = 118;
const ERR_INVALID_HASH = 119;
const ERR_INVALID_PROOF_ID = 120;

interface Proof {
  user: string;
  issuer: string;
  proofHash: Uint8Array;
  publicInput: Uint8Array;
  timestamp: number;
  expiry: number;
  status: boolean;
  vaccineType: string;
  doseCount: number;
  challenge: Uint8Array;
  vkParams: Uint8Array;
}

interface Issuer {
  name: string;
  verified: boolean;
  sigKey: Uint8Array;
}

interface VerificationLog {
  proofId: number;
  verifier: string;
  timestamp: number;
  result: boolean;
}

interface Result<T> {
  ok: boolean;
  value: T;
}

class VerificationEngineMock {
  state: {
    nextProofId: number;
    maxProofs: number;
    verificationFee: number;
    adminPrincipal: string;
    proofs: Map<number, Proof>;
    proofsByHash: Map<string, number>;
    issuers: Map<string, Issuer>;
    verificationLogs: Map<number, VerificationLog>;
  } = {
    nextProofId: 0,
    maxProofs: 10000,
    verificationFee: 500,
    adminPrincipal: "ST1ADMIN",
    proofs: new Map(),
    proofsByHash: new Map(),
    issuers: new Map(),
    verificationLogs: new Map(),
  };
  blockHeight: number = 0;
  caller: string = "ST1USER";
  stxTransfers: Array<{ amount: number; from: string; to: string }> = [];

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      nextProofId: 0,
      maxProofs: 10000,
      verificationFee: 500,
      adminPrincipal: "ST1ADMIN",
      proofs: new Map(),
      proofsByHash: new Map(),
      issuers: new Map(),
      verificationLogs: new Map(),
    };
    this.blockHeight = 0;
    this.caller = "ST1USER";
    this.stxTransfers = [];
  }

  registerIssuer(name: string, sigKey: Uint8Array): Result<boolean> {
    if (this.caller !== this.state.adminPrincipal) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (this.state.issuers.has(this.caller)) return { ok: false, value: ERR_ISSUER_NOT_REGISTERED };
    this.state.issuers.set(this.caller, { name, verified: true, sigKey });
    return { ok: true, value: true };
  }

  submitProof(
    proofHash: Uint8Array,
    publicInput: Uint8Array,
    expiry: number,
    vaccineType: string,
    doseCount: number,
    challenge: Uint8Array,
    vkParams: Uint8Array,
    issuerSig: Uint8Array
  ): Result<number> {
    if (this.state.nextProofId >= this.state.maxProofs) return { ok: false, value: ERR_MAX_PROOFS_EXCEEDED };
    if (proofHash.length !== 32) return { ok: false, value: ERR_INVALID_HASH };
    if (publicInput.length !== 64) return { ok: false, value: ERR_INVALID_PUBLIC_INPUT };
    if (expiry <= this.blockHeight) return { ok: false, value: ERR_INVALID_EXPIRY };
    if (!["COVID-19", "FLU", "HEPATITIS"].includes(vaccineType)) return { ok: false, value: ERR_INVALID_VACCINE_TYPE };
    if (doseCount < 1 || doseCount > 5) return { ok: false, value: ERR_INVALID_DOSE_COUNT };
    if (challenge.length !== 32) return { ok: false, value: ERR_INVALID_CHALLENGE };
    if (vkParams.length !== 128) return { ok: false, value: ERR_INVALID_VK_PARAMS };
    if (issuerSig.length !== 65) return { ok: false, value: ERR_INVALID_ISSUER_SIG };
    if (!this.state.issuers.has(this.caller)) return { ok: false, value: ERR_ISSUER_NOT_REGISTERED };
    const hashKey = new TextDecoder().decode(proofHash);
    if (this.state.proofsByHash.has(hashKey)) return { ok: false, value: ERR_PROOF_ALREADY_USED };

    this.stxTransfers.push({ amount: this.state.verificationFee, from: this.caller, to: this.state.adminPrincipal });

    const id = this.state.nextProofId;
    const proof: Proof = {
      user: this.caller,
      issuer: this.caller,
      proofHash,
      publicInput,
      timestamp: this.blockHeight,
      expiry,
      status: true,
      vaccineType,
      doseCount,
      challenge,
      vkParams,
    };
    this.state.proofs.set(id, proof);
    this.state.proofsByHash.set(hashKey, id);
    this.state.nextProofId++;
    return { ok: true, value: id };
  }

  getProof(id: number): Proof | undefined {
    return this.state.proofs.get(id);
  }

  verifyProof(id: number, proof: Uint8Array, publicInput: Uint8Array): Result<boolean> {
    const proofData = this.state.proofs.get(id);
    if (!proofData) return { ok: false, value: ERR_INVALID_PROOF_ID };
    if (!proofData.status) return { ok: false, value: ERR_INVALID_STATUS };
    if (this.blockHeight >= proofData.expiry) return { ok: false, value: ERR_PROOF_EXPIRED };
    if (proof.length !== 256) return { ok: false, value: ERR_INVALID_PROOF_LENGTH };
    if (publicInput.length !== 64) return { ok: false, value: ERR_INVALID_PUBLIC_INPUT };
    if (new TextDecoder().decode(publicInput) !== new TextDecoder().decode(proofData.publicInput)) return { ok: false, value: ERR_INVALID_PUBLIC_INPUT };

    const logId = this.state.nextProofId;
    this.state.verificationLogs.set(logId, {
      proofId: id,
      verifier: this.caller,
      timestamp: this.blockHeight,
      result: true,
    });
    return { ok: true, value: true };
  }

  revokeProof(id: number): Result<boolean> {
    const proofData = this.state.proofs.get(id);
    if (!proofData) return { ok: false, value: ERR_INVALID_PROOF_ID };
    if (proofData.issuer !== this.caller) return { ok: false, value: ERR_NOT_AUTHORIZED };
    this.state.proofs.set(id, { ...proofData, status: false });
    return { ok: true, value: true };
  }

  setVerificationFee(newFee: number): Result<boolean> {
    if (this.caller !== this.state.adminPrincipal) return { ok: false, value: ERR_NOT_AUTHORIZED };
    this.state.verificationFee = newFee;
    return { ok: true, value: true };
  }

  getProofCount(): Result<number> {
    return { ok: true, value: this.state.nextProofId };
  }
}

describe("VerificationEngine", () => {
  let contract: VerificationEngineMock;

  beforeEach(() => {
    contract = new VerificationEngineMock();
    contract.reset();
  });

  it("registers issuer successfully", () => {
    contract.caller = "ST1ADMIN";
    const sigKey = new Uint8Array(33).fill(0);
    const result = contract.registerIssuer("HealthOrg", sigKey);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.issuers.get("ST1ADMIN")?.name).toBe("HealthOrg");
  });

  it("submits proof successfully", () => {
    contract.caller = "ST1ISSUER";
    const sigKey = new Uint8Array(33).fill(0);
    contract.state.issuers.set("ST1ISSUER", { name: "Issuer", verified: true, sigKey });
    const proofHash = new Uint8Array(32).fill(1);
    const publicInput = new Uint8Array(64).fill(2);
    const challenge = new Uint8Array(32).fill(3);
    const vkParams = new Uint8Array(128).fill(4);
    const issuerSig = new Uint8Array(65).fill(5);
    const result = contract.submitProof(proofHash, publicInput, 100, "COVID-19", 2, challenge, vkParams, issuerSig);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(0);
    const proof = contract.getProof(0);
    expect(proof?.vaccineType).toBe("COVID-19");
    expect(proof?.doseCount).toBe(2);
    expect(contract.stxTransfers).toEqual([{ amount: 500, from: "ST1ISSUER", to: "ST1ADMIN" }]);
  });

  it("rejects duplicate proof hash", () => {
    contract.caller = "ST1ISSUER";
    const sigKey = new Uint8Array(33).fill(0);
    contract.state.issuers.set("ST1ISSUER", { name: "Issuer", verified: true, sigKey });
    const proofHash = new Uint8Array(32).fill(1);
    const publicInput = new Uint8Array(64).fill(2);
    const challenge = new Uint8Array(32).fill(3);
    const vkParams = new Uint8Array(128).fill(4);
    const issuerSig = new Uint8Array(65).fill(5);
    contract.submitProof(proofHash, publicInput, 100, "COVID-19", 2, challenge, vkParams, issuerSig);
    const result = contract.submitProof(proofHash, publicInput, 200, "FLU", 1, challenge, vkParams, issuerSig);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_PROOF_ALREADY_USED);
  });

  it("verifies proof successfully", () => {
    contract.caller = "ST1ISSUER";
    const sigKey = new Uint8Array(33).fill(0);
    contract.state.issuers.set("ST1ISSUER", { name: "Issuer", verified: true, sigKey });
    const proofHash = new Uint8Array(32).fill(1);
    const publicInput = new Uint8Array(64).fill(2);
    const challenge = new Uint8Array(32).fill(3);
    const vkParams = new Uint8Array(128).fill(4);
    const issuerSig = new Uint8Array(65).fill(5);
    contract.submitProof(proofHash, publicInput, 100, "COVID-19", 2, challenge, vkParams, issuerSig);
    const proof = new Uint8Array(256).fill(6);
    const result = contract.verifyProof(0, proof, publicInput);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
  });

  it("rejects verification for expired proof", () => {
    contract.caller = "ST1ISSUER";
    const sigKey = new Uint8Array(33).fill(0);
    contract.state.issuers.set("ST1ISSUER", { name: "Issuer", verified: true, sigKey });
    const proofHash = new Uint8Array(32).fill(1);
    const publicInput = new Uint8Array(64).fill(2);
    const challenge = new Uint8Array(32).fill(3);
    const vkParams = new Uint8Array(128).fill(4);
    const issuerSig = new Uint8Array(65).fill(5);
    contract.submitProof(proofHash, publicInput, 50, "COVID-19", 2, challenge, vkParams, issuerSig);
    contract.blockHeight = 60;
    const proof = new Uint8Array(256).fill(6);
    const result = contract.verifyProof(0, proof, publicInput);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_PROOF_EXPIRED);
  });

  it("revokes proof successfully", () => {
    contract.caller = "ST1ISSUER";
    const sigKey = new Uint8Array(33).fill(0);
    contract.state.issuers.set("ST1ISSUER", { name: "Issuer", verified: true, sigKey });
    const proofHash = new Uint8Array(32).fill(1);
    const publicInput = new Uint8Array(64).fill(2);
    const challenge = new Uint8Array(32).fill(3);
    const vkParams = new Uint8Array(128).fill(4);
    const issuerSig = new Uint8Array(65).fill(5);
    contract.submitProof(proofHash, publicInput, 100, "COVID-19", 2, challenge, vkParams, issuerSig);
    const result = contract.revokeProof(0);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    const proof = contract.getProof(0);
    expect(proof?.status).toBe(false);
  });

  it("sets verification fee successfully", () => {
    contract.caller = "ST1ADMIN";
    const result = contract.setVerificationFee(1000);
    expect(result.ok).toBe(true);
    expect(result.value).toBe(true);
    expect(contract.state.verificationFee).toBe(1000);
  });

  it("returns correct proof count", () => {
    contract.caller = "ST1ISSUER";
    const sigKey = new Uint8Array(33).fill(0);
    contract.state.issuers.set("ST1ISSUER", { name: "Issuer", verified: true, sigKey });
    const proofHash1 = new Uint8Array(32).fill(1);
    const proofHash2 = new Uint8Array(32).fill(7);
    const publicInput = new Uint8Array(64).fill(2);
    const challenge = new Uint8Array(32).fill(3);
    const vkParams = new Uint8Array(128).fill(4);
    const issuerSig = new Uint8Array(65).fill(5);
    contract.submitProof(proofHash1, publicInput, 100, "COVID-19", 2, challenge, vkParams, issuerSig);
    contract.submitProof(proofHash2, publicInput, 200, "FLU", 1, challenge, vkParams, issuerSig);
    const result = contract.getProofCount();
    expect(result.ok).toBe(true);
    expect(result.value).toBe(2);
  });
  
  it("rejects submit with invalid vaccine type", () => {
    contract.caller = "ST1ISSUER";
    const sigKey = new Uint8Array(33).fill(0);
    contract.state.issuers.set("ST1ISSUER", { name: "Issuer", verified: true, sigKey });
    const proofHash = new Uint8Array(32).fill(1);
    const publicInput = new Uint8Array(64).fill(2);
    const challenge = new Uint8Array(32).fill(3);
    const vkParams = new Uint8Array(128).fill(4);
    const issuerSig = new Uint8Array(65).fill(5);
    const result = contract.submitProof(proofHash, publicInput, 100, "INVALID", 2, challenge, vkParams, issuerSig);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_VACCINE_TYPE);
  });

  it("rejects max proofs exceeded", () => {
    contract.caller = "ST1ISSUER";
    const sigKey = new Uint8Array(33).fill(0);
    contract.state.issuers.set("ST1ISSUER", { name: "Issuer", verified: true, sigKey });
    contract.state.maxProofs = 1;
    const proofHash = new Uint8Array(32).fill(1);
    const publicInput = new Uint8Array(64).fill(2);
    const challenge = new Uint8Array(32).fill(3);
    const vkParams = new Uint8Array(128).fill(4);
    const issuerSig = new Uint8Array(65).fill(5);
    contract.submitProof(proofHash, publicInput, 100, "COVID-19", 2, challenge, vkParams, issuerSig);
    const result = contract.submitProof(proofHash, publicInput, 200, "FLU", 1, challenge, vkParams, issuerSig);
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_MAX_PROOFS_EXCEEDED);
  });
});