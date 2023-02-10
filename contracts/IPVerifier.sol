pragma solidity ^0.7.0;
pragma experimental ABIEncoderV2;

import './library/BN128.sol';

contract IPVerifier {
    using BN128 for BN128.G1Point;
    using BN128 for uint256;

    // IPProof contains proof to verify inner product.
    struct IPProof {
        uint256[] l;
        uint256[] r;
        uint256 a;
        uint256 b;
    }

    // for tmp calculation.
    struct Board {
        BN128.G1Point tmpl;
        BN128.G1Point tmpr;
        BN128.G1Point f;
        BN128.G1Point s;
        BN128.G1Point tmpgv;
        BN128.G1Point tmphv;
        uint256 index;
        uint256[] challenges;
        uint256[] challengesInverse;
    }

    struct CalResult {
        BN128.G1Point ue;
        BN128.G1Point np;
        IPProof proof;
    }

    /*
     */
    function optimizedVerifyIPProof(
        uint256[] memory gv,
        uint256[] memory hv,
        uint256[2] memory p,
        uint256[2] memory u,
        uint256 c,
        uint256[] memory l,
        uint256[] memory r,
        uint256 a,
        uint256 b
    ) public view returns (bool) {
        CalResult memory cal;
        bool valid;
        (valid, cal) = basicCheck(gv, hv, p, u, c, l, r, a, b);
        if (!valid) {
            return false;
        }

        return verifyIPProofMulti(gv, hv, cal.ue, cal.np, cal.proof);
    }

    /*
     * @dev call by range proof.
     * @dev gv size must equal with hv size, lsize equal with r size and 2^lsize = gv size.
     * @dev Warning: hv isn't the public h vector generator.
     */
    function verifyIPProof(
        uint256[] memory gv,
        uint256[] memory hv,
        uint256[2] memory p,
        uint256[2] memory u,
        uint256 c,
        uint256[] memory l,
        uint256[] memory r,
        uint256 a,
        uint256 b
    ) public view returns (bool) {
        CalResult memory cal;
        bool valid;
        (valid, cal) = basicCheck(gv, hv, p, u, c, l, r, a, b);
        if (!valid) {
            return false;
        }

        return verifyIPProofNormal(gv, hv, cal.ue, cal.np, cal.proof);
    }

    function basicCheck(
        uint256[] memory gv,
        uint256[] memory hv,
        uint256[2] memory p,
        uint256[2] memory u,
        uint256 c,
        uint256[] memory l,
        uint256[] memory r,
        uint256 a,
        uint256 b
    ) internal view returns (bool, CalResult memory) {
        // for simple check.
        CalResult memory cal;
        if (gv.length != hv.length || l.length != r.length) {
            return (false, cal);
        }

        if (2**(l.length / 2) != gv.length / 2) {
            return (false, cal);
        }

        cal.proof.l = new uint256[](l.length);
        cal.proof.r = new uint256[](l.length);
        for (uint256 i = 0; i < l.length; i++) {
            cal.proof.l[i] = l[i];
            cal.proof.r[i] = r[i];
        }

        cal.proof.a = a;
        cal.proof.b = b;

        // compute challenge e.
        uint256 e = computeChallengeStep1(c);

        cal.ue = BN128.G1Point(u[0], u[1]).mul(e);
        cal.np = cal.ue.mul(c).add(BN128.G1Point(p[0], p[1]));

        return (true, cal);
    }

    function verifyIPProofMulti(
        uint256[] memory gv,
        uint256[] memory hv,
        BN128.G1Point memory newU,
        BN128.G1Point memory p,
        IPProof memory proof
    ) internal view returns (bool) {
        Board memory b;
        b.challenges = new uint256[](proof.l.length / 2);
        b.challengesInverse = new uint256[](proof.l.length / 2);
        // compute formula on the right.
        // compute p + li * xi^2 + ri * xi^-2.
        for (uint256 i = 0; i < proof.l.length / 2; i++) {
            b.tmpl = BN128.G1Point(proof.l[2 * i], proof.l[2 * i + 1]);
            b.tmpr = BN128.G1Point(proof.r[2 * i], proof.r[2 * i + 1]);
            uint256 x = computeChallengeStep2(proof.l[2 * i], proof.l[2 * i + 1], proof.r[2 * i], proof.r[2 * i + 1]);
            uint256 xInverse = x.inv();
            b.challenges[i] = x;
            b.challengesInverse[i] = xInverse;
            p = p.add(b.tmpl.mul(x.mul(x))).add(b.tmpr.mul(xInverse.mul(xInverse)));
        }

        // compute formula on the left.
        // compute g*s*a + h*s^-1*b + u*a*b.

        // compute s.
        uint256[] memory s = new uint256[](gv.length / 2);
        for (uint256 i = 0; i < gv.length / 2; i++) {
            for (uint256 j = 0; j < proof.l.length / 2; j++) {
                uint256 tmp;

                if (smallParseBinary(i, j, proof.l.length / 2)) {
                    tmp = b.challenges[j];
                } else {
                    tmp = b.challengesInverse[j];
                }

                if (j == 0) {
                    s[i] = tmp;
                } else {
                    s[i] = s[i].mul(tmp).mod();
                }
            }
        }

        BN128.G1Point memory left;
        left = multiExp(gv, s).mul(proof.a).add(multiExpInverse(hv, s).mul(proof.b)).add(
            newU.mul(proof.a.mul(proof.b))
        );

        return left.X == p.X && left.Y == p.Y;
    }

    function verifyIPProofNormal(
        uint256[] memory gv,
        uint256[] memory hv,
        BN128.G1Point memory newU,
        BN128.G1Point memory p,
        IPProof memory proof
    ) internal view returns (bool) {
        Board memory b;
        uint256 step = 2;

        for (uint256 i = 0; i < proof.l.length / 2; i++) {
            b.tmpl = BN128.G1Point(proof.l[2 * i], proof.l[2 * i + 1]);
            b.tmpr = BN128.G1Point(proof.r[2 * i], proof.r[2 * i + 1]);
            uint256 e = computeChallengeStep2(proof.l[2 * i], proof.l[2 * i + 1], proof.r[2 * i], proof.r[2 * i + 1]);
            uint256 eInverse = e.inv();

            for (uint256 j = 0; j < gv.length / 2 / step; j++) {
                // compute gv prime.
                b.index = gv.length / 2 / step + j;
                b.f = BN128.G1Point(gv[2 * j], gv[2 * j + 1]);
                b.s = BN128.G1Point(gv[b.index * 2], gv[b.index * 2 + 1]);

                b.tmpgv = b.f.mul(eInverse).add(b.s.mul(e));
                gv[j * 2] = b.tmpgv.X;
                gv[j * 2 + 1] = b.tmpgv.Y;

                // compute hv prime.
                b.f = BN128.G1Point(hv[2 * j], hv[2 * j + 1]);
                b.s = BN128.G1Point(hv[b.index * 2], hv[b.index * 2 + 1]);
                b.tmphv = b.f.mul(e).add(b.s.mul(eInverse));
                hv[j * 2] = b.tmphv.X;
                hv[j * 2 + 1] = b.tmphv.Y;
            }

            // compute p points.
            // p' = l*x^2 + r^*xInv^2 + p.
            p = b.tmpl.mul(e.mul(e).mod()).add(b.tmpr.mul(eInverse.mul(eInverse).mod())).add(p);

            step = step * 2;
        }

        // c = a * b;
        uint256 c = proof.a.mul(proof.b).mod();

        // want = gv[0]*a + hv[0]*b + u*c.
        b.f = BN128.G1Point(gv[0], gv[1]);
        b.s = BN128.G1Point(hv[0], hv[1]);
        BN128.G1Point memory want = newU.mul(c).add(b.f.mul(proof.a)).add(b.s.mul(proof.b));

        return p.X == want.X && p.Y == want.Y;
    }

    function computeChallengeStep1(uint256 a) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(a))).mod();
    }

    function computeChallengeStep2(
        uint256 a,
        uint256 b,
        uint256 c,
        uint256 d
    ) internal pure returns (uint256) {
        return uint256(keccak256(abi.encodePacked(a, b, c, d))).mod();
    }

    function smallParseBinary(
        uint256 t,
        uint256 j,
        uint256 size
    ) internal pure returns (bool) {
        uint256 w = 1 << (size - 1);

        for (uint256 i = 0; i < j; i++) {
            w = w >> 1;
        }

        if ((t & w) != 0) {
            return true;
        }

        return false;
    }

    function multiExp(uint256[] memory base, uint256[] memory exp) internal view returns (BN128.G1Point memory) {
        BN128.G1Point memory res;
        res = BN128.G1Point(base[0], base[1]).mul(exp[0]);
        for (uint256 i = 1; i < exp.length; i++) {
            res = res.add(BN128.G1Point(base[2 * i], base[2 * i + 1]).mul(exp[i]));
        }

        return res;
    }

    function multiExpInverse(uint256[] memory base, uint256[] memory exp) internal view returns (BN128.G1Point memory) {
        uint256[] memory expInverse = new uint256[](exp.length);
        for (uint256 i = 0; i < exp.length; i++) {
            expInverse[i] = exp[i].inv();
        }

        return multiExp(base, expInverse);
    }
}
