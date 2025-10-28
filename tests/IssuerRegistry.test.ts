import { describe, it, expect, beforeEach } from "vitest";
import { buffCV, stringUtf8CV, uintCV } from "@stacks/transactions";

const ERR_NOT_AUTHORIZED = 200;
const ERR_ISSUER_EXISTS = 201;
const ERR_ISSUER_NOT_FOUND = 202;
const ERR_INVALID_NAME = 203;
const ERR_INVALID_LOCATION = 204;
const ERR_INVALID_CREDENTIAL = 205;
const ERR_INVALID_PUBLIC_KEY = 206;
const ERR_MAX_ISSUERS_EXCEEDED = 208;
const ERR_INVALID_VERIFICATION_METHOD = 209;

interface Issuer {
  name: string;
  location: string;
  credentialHash: Uint8Array;
  publicKey: Uint8Array;
  status: boolean;
  verificationMethod: string;
  registeredAt: number;
  updatedAt: number;
}

interface Result<T> {
  ok: boolean;
  value: T;
}

class IssuerRegistryMock {
  state: {
    nextIssuerId: number;
    maxIssuers: number;
    adminPrincipal: string;
    issuers: Map<number, Issuer>;
    issuersByPrincipal: Map<string, number>;
    issuersByName: Map<string, number>;
  } = {
    nextIssuerId: 0,
    maxIssuers: 500,
    adminPrincipal: "ST1ADMIN",
    issuers: new Map(),
    issuersByPrincipal: new Map(),
    issuersByName: new Map(),
  };
  blockHeight: number = 0;
  caller: string = "ST1ISSUER";

  constructor() {
    this.reset();
  }

  reset() {
    this.state = {
      nextIssuerId: 0,
      maxIssuers: 500,
      adminPrincipal: "ST1ADMIN",
      issuers: new Map(),
      issuersByPrincipal: new Map(),
      issuersByName: new Map(),
    };
    this.blockHeight = 0;
    this.caller = "ST1ISSUER";
  }

  registerIssuer(
    name: string,
    location: string,
    credentialHash: Uint8Array,
    publicKey: Uint8Array,
    verificationMethod: string
  ): Result<number> {
    if (this.state.nextIssuerId >= this.state.maxIssuers) return { ok: false, value: ERR_MAX_ISSUERS_EXCEEDED };
    if (!name || name.length > 100) return { ok: false, value: ERR_INVALID_NAME };
    if (!location || location.length > 100) return { ok: false, value: ERR_INVALID_LOCATION };
    if (credentialHash.length !== 32) return { ok: false, value: ERR_INVALID_CREDENTIAL };
    if (publicKey.length !== 33) return { ok: false, value: ERR_INVALID_PUBLIC_KEY };
    if (!["WHO", "CDC", "EU-DCC", "ICAO"].includes(verificationMethod)) return { ok: false, value: ERR_INVALID_VERIFICATION_METHOD };
    if (this.state.issuersByName.has(name)) return { ok: false, value: ERR_ISSUER_EXISTS };
    if (this.state.issuersByPrincipal.has(this.caller)) return { ok: false, value: ERR_ISSUER_EXISTS };

    const id = this.state.nextIssuerId;
    const issuer: Issuer = {
      name,
      location,
      credentialHash,
      publicKey,
      status: true,
      verificationMethod,
      registeredAt: this.blockHeight,
      updatedAt: this.blockHeight,
    };
    this.state.issuers.set(id, issuer);
    this.state.issuersByPrincipal.set(this.caller, id);
    this.state.issuersByName.set(name, id);
    this.state.nextIssuerId++;
    return { ok: true, value: id };
  }

  getIssuerById(id: number): Issuer | undefined {
    return this.state.issuers.get(id);
  }

  updateIssuer(
    issuerId: number,
    name: string,
    location: string,
    verificationMethod: string
  ): Result<boolean> {
    const issuer = this.state.issuers.get(issuerId);
    if (!issuer) return { ok: false, value: ERR_ISSUER_NOT_FOUND };
    const principalId = this.state.issuersByPrincipal.get(this.caller);
    if (!principalId || principalId !== issuerId) return { ok: false, value: ERR_NOT_AUTHORIZED };
    if (!name || name.length > 100) return { ok: false, value: ERR_INVALID_NAME };
    if (!location || location.length > 100) return { ok: false, value: ERR_INVALID_LOCATION };
    if (!["WHO", "CDC", "EU-DCC", "ICAO"].includes(verificationMethod)) return { ok: false, value: ERR_INVALID_VERIFICATION_METHOD };

    if (this.state.issuersByName.has(name) && this.state.issuersByName.get(name) !== issuerId) {
      return { ok: false, value: ERR_ISSUER_EXISTS };
    }

    const oldName = issuer.name;
    if (oldName !== name) {
      this.state.issuersByName.delete(oldName);
      this.state.issuersByName.set(name, issuerId);
    }

    const updated: Issuer = {
      ...issuer,
      name,
      location,
      verificationMethod,
      updatedAt: this.blockHeight,
    };
    this.state.issuers.set(issuerId, updated);
    return { ok: true, value: true };
  }

  deactivateIssuer(issuerId: number): Result<boolean> {
    if (this.caller !== this.state.adminPrincipal) return { ok: false, value: ERR_NOT_AUTHORIZED };
    const issuer = this.state.issuers.get(issuerId);
    if (!issuer) return { ok: false, value: ERR_ISSUER_NOT_FOUND };
    this.state.issuers.set(issuerId, { ...issuer, status: false, updatedAt: this.blockHeight });
    return { ok: true, value: true };
  }

  reactivateIssuer(issuerId: number): Result<boolean> {
    if (this.caller !== this.state.adminPrincipal) return { ok: false, value: ERR_NOT_AUTHORIZED };
    const issuer = this.state.issuers.get(issuerId);
    if (!issuer) return { ok: false, value: ERR_ISSUER_NOT_FOUND };
    this.state.issuers.set(issuerId, { ...issuer, status: true, updatedAt: this.blockHeight });
    return { ok: true, value: true };
  }

  setAdmin(newAdmin: string): Result<boolean> {
    if (this.caller !== this.state.adminPrincipal) return { ok: false, value: ERR_NOT_AUTHORIZED };
    this.state.adminPrincipal = newAdmin;
    return { ok: true, value: true };
  }

  getIssuerCount(): Result<number> {
    return { ok: true, value: this.state.nextIssuerId };
  }
}

describe("IssuerRegistry", () => {
  let contract: IssuerRegistryMock;

  beforeEach(() => {
    contract = new IssuerRegistryMock();
    contract.reset();
  });

  it("registers issuer successfully", () => {
    const cred = new Uint8Array(32).fill(1);
    const pub = new Uint8Array(33).fill(2);
    const result = contract.registerIssuer("WHO Clinic", "Geneva", cred, pub, "WHO");
    expect(result.ok).toBe(true);
    expect(result.value).toBe(0);
    const issuer = contract.getIssuerById(0);
    expect(issuer?.name).toBe("WHO Clinic");
    expect(issuer?.verificationMethod).toBe("WHO");
    expect(issuer?.status).toBe(true);
  });

  it("rejects duplicate name", () => {
    const cred = new Uint8Array(32).fill(1);
    const pub = new Uint8Array(33).fill(2);
    contract.registerIssuer("CDC", "Atlanta", cred, pub, "CDC");
    const result = contract.registerIssuer("CDC", "DC", cred, pub, "CDC");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_ISSUER_EXISTS);
  });

  it("rejects duplicate principal", () => {
    const cred = new Uint8Array(32).fill(1);
    const pub = new Uint8Array(33).fill(2);
    contract.registerIssuer("ClinicA", "NY", cred, pub, "ICAO");
    const result = contract.registerIssuer("ClinicB", "LA", cred, pub, "ICAO");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_ISSUER_EXISTS);
    });

  it("rejects update by non-owner", () => {
    const cred = new Uint8Array(32).fill(1);
    const pub = new Uint8Array(33).fill(2);
    contract.registerIssuer("Hospital", "London", cred, pub, "WHO");
    contract.caller = "ST2OTHER";
    const result = contract.updateIssuer(0, "New Name", "Berlin", "WHO");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_NOT_AUTHORIZED);
  });

  it("deactivates issuer by admin", () => {
    const cred = new Uint8Array(32).fill(1);
    const pub = new Uint8Array(33).fill(2);
    contract.registerIssuer("Clinic", "Tokyo", cred, pub, "ICAO");
    contract.caller = "ST1ADMIN";
    const result = contract.deactivateIssuer(0);
    expect(result.ok).toBe(true);
    const issuer = contract.getIssuerById(0);
    expect(issuer?.status).toBe(false);
  });

  it("reactivates issuer by admin", () => {
    const cred = new Uint8Array(32).fill(1);
    const pub = new Uint8Array(33).fill(2);
    contract.registerIssuer("Center", "Seoul", cred, pub, "CDC");
    contract.caller = "ST1ADMIN";
    contract.deactivateIssuer(0);
    const result = contract.reactivateIssuer(0);
    expect(result.ok).toBe(true);
    const issuer = contract.getIssuerById(0);
    expect(issuer?.status).toBe(true);
  });

  it("changes admin successfully", () => {
    contract.caller = "ST1ADMIN";
    const result = contract.setAdmin("ST2NEWADMIN");
    expect(result.ok).toBe(true);
    expect(contract.state.adminPrincipal).toBe("ST2NEWADMIN");
  });

  it("rejects invalid verification method", () => {
    const cred = new Uint8Array(32).fill(1);
    const pub = new Uint8Array(33).fill(2);
    const result = contract.registerIssuer("Invalid", "Place", cred, pub, "XYZ");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_INVALID_VERIFICATION_METHOD);
  });

  it("rejects max issuers exceeded", () => {
    contract.state.maxIssuers = 1;
    const cred = new Uint8Array(32).fill(1);
    const pub = new Uint8Array(33).fill(2);
    contract.registerIssuer("One", "Loc", cred, pub, "WHO");
    const result = contract.registerIssuer("Two", "Loc", cred, pub, "CDC");
    expect(result.ok).toBe(false);
    expect(result.value).toBe(ERR_MAX_ISSUERS_EXCEEDED);
  });
});