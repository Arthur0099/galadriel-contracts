const {
  expect
} = require("chai");
const {
  ethers
} = require("hardhat");

const {
  GetInnerProductParams,
  GetInnerProductCommit,
  GetInnerProductionProof
} = require("./utils.js");

describe("inner product", function () {
  let params = GetInnerProductParams("../proofs/innerProductParams.json");
  let commit = GetInnerProductCommit("../proofs/innerProductCommit.json")
  let proof = GetInnerProductionProof("../proofs/innerProductProof.json");

  before(async function () {
    const IPVerifier = await ethers.getContractFactory("IPVerifier");
    this.IPVerifierIns = await IPVerifier.deploy();
  });

  it("optimized verify check", async function () {
    expect(await this.IPVerifierIns.optimizedVerifyIPProof(
      params.gv,
      params.hv,
      commit.p,
      params.u,
      commit.c,
      proof.l,
      proof.r,
      proof.a,
      proof.b,
    )).to.be.equal(true);
  })

  it("normal verify check", async function () {
    expect(await this.IPVerifierIns.verifyIPProof(
      params.gv,
      params.hv,
      commit.p,
      params.u,
      commit.c,
      proof.l,
      proof.r,
      proof.a,
      proof.b,
    )).to.be.equal(true);
  })
});