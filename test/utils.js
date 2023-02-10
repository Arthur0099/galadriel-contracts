const fs = require('fs');
const {
    ethers
} = require("hardhat");

function LoadJson(path) {
    let rawdata = fs.readFileSync(__dirname + "/" + path);
    return JSON.parse(rawdata);
}

module.exports.GetBurnTx = function (path) {
    let burnTx = LoadJson(path);

    let out = {};
    out.receiver = burnTx.Receiver;
    out.amount = burnTx.Amount;
    out.points = burnTx.Points;
    out.z = burnTx.Z;

    return out;
}

module.exports.GetTestCase = function (path) {
    let testcase = LoadJson(path);

    let out = {};
    out.alice = testcase.Alice;
    out.bob = testcase.Bob;

    out.depositAmount = testcase.DepositAmount;
    out.aliceBurnExpect = testcase.AliceBurnExpect;
    out.bobBurnExpect = testcase.BobBurnExpect;

    return out;
}

module.exports.GetCtx = function (path) {
    let ctx = LoadJson(path);

    let out = {};
    out.points = ctx.Points;
    out.lr = ctx.Lr;

    out.scalars = [10];
    for (let i = 0; i < 10; i++) {
        out.scalars[i] = ctx.Scalars[i];
    }

    return out
}

module.exports.GetPub = function (path) {
    let params = LoadJson(path);

    let out = {};
    out.x = params.Pub.X;
    out.y = params.Pub.Y;

    return out;
}

module.exports.GetInnerProductionProof = function (path) {
    let proof = LoadJson(path);
    let out = {};

    out.l = [];
    for (let i = 0; i < proof.L.length; i++) {
        out.l.push(proof.L[i].X);
        out.l.push(proof.L[i].Y);
    }

    out.r = [];
    for (let i = 0; i < proof.R.length; i++) {
        out.r.push(proof.R[i].X);
        out.r.push(proof.R[i].Y);
    }

    out.a = proof.A;
    out.b = proof.B;
    return out;
}

module.exports.GetInnerProductCommit = function (path) {
    let commit = LoadJson(path);
    let out = {};

    out.p = [2];
    out.p[0] = commit.P.X;
    out.p[1] = commit.P.Y;

    out.c = commit.C;
    return out;
}

module.exports.GetInnerProductParams = function (path) {
    let params = LoadJson(path);
    let out = {};

    out.gv = [];
    for (let i = 0; i < params.GV.Vec.length; i++) {
        out.gv.push(params.GV.Vec[i].X);
        out.gv.push(params.GV.Vec[i].Y);
    }

    out.hv = [];
    for (let i = 0; i < params.HV.Vec.length; i++) {
        out.hv.push(params.HV.Vec[i].X);
        out.hv.push(params.HV.Vec[i].Y);
    }

    out.u = [2];
    out.u[0] = params.U.X;
    out.u[1] = params.U.Y;

    return out;
};