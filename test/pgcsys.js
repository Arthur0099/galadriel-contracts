const {
    expect
} = require("chai");
const {
    ethers
} = require("hardhat");

const {
    GetPub,
    GetTestCase,
    GetCtx,
    GetBurnTx,
} = require("./utils.js");

describe("pgc sys", function () {
    const provider = ethers.provider;
    let pub = GetPub("../proofs/params.json");
    let alice, bob;
    let ctx = GetCtx("../proofs/transferCtx.json");
    let testCase = GetTestCase("../proofs/testCase.json");
    let aliceBurnTx = GetBurnTx("../proofs/aliceBurnTx.json");
    let bobBurnTx = GetBurnTx("../proofs/bobBurnTx.json");
    before("deploy contracts", async function () {
        let signers = await ethers.getSigners();
        alice = signers[1];
        bob = signers[2];
        const PublicParams = await ethers.getContractFactory("PublicParams");
        this.params = await PublicParams.deploy(pub.x, pub.y);
        const TokenConverter = await ethers.getContractFactory("TokenConverter");
        this.tokenConverter = await TokenConverter.deploy();
        const Verifier = await ethers.getContractFactory("Verifier");
        this.verify = await Verifier.deploy(this.params.address);
        await this.verify.init(32);
        const PGC = await ethers.getContractFactory("PGC");
        this.pgc = await PGC.deploy(this.params.address, this.verify.address, this.tokenConverter.address);
    })

    it("deposit check", async function () {
        await expect(this.pgc.connect(alice).depositAccountETH(testCase.alice, {
            value: ethers.BigNumber.from(testCase.depositAmount),
        })).to.be.emit(this.pgc, "LogDepositAccount");
        await expect(this.pgc.connect(alice).depositAccountETH(testCase.bob, {
            value: ethers.BigNumber.from(testCase.depositAmount),
        })).to.be.emit(this.pgc, "LogDepositAccount");
    })

    it("transfer check", async function () {
        await expect(this.pgc.connect(alice).aggTransferETH(
            ctx.points,
            ctx.scalars,
            ctx.lr,
        )).to.be.emit(this.pgc, "LogAggTransfer");
    })

    it("alice burn check", async function () {
        await expect(this.pgc.connect(alice).burnETH(
            aliceBurnTx.receiver,
            aliceBurnTx.amount,
            aliceBurnTx.points,
            aliceBurnTx.z,
        )).to.be.emit(this.pgc, "LogBurn");

        // check amount
        let amount = await provider.getBalance(aliceBurnTx.receiver);
        expect(amount.toString()).to.be.equal(testCase.aliceBurnExpect);
    })

    it("bob burn check", async function () {
        await expect(this.pgc.connect(bob).burnETH(
            bobBurnTx.receiver,
            bobBurnTx.amount,
            bobBurnTx.points,
            bobBurnTx.z,
        )).to.be.emit(this.pgc, "LogBurn");

        // check amount
        let amount = await provider.getBalance(bobBurnTx.receiver);
        expect(amount.toString()).to.be.equal(testCase.bobBurnExpect);
    })
})