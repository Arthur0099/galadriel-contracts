pragma solidity >= 0.5.0 < 0.6.0;
pragma experimental ABIEncoderV2;

import "./library/BN128.sol";

contract IPVerifier {
  using BN128 for BN128.G1Point;
  using BN128 for uint;

  // IPProof contains proof to verify inner product.
  struct IPProof {
    uint[] l;
    uint[] r;
    uint a;
    uint b;
  }

  // for tmp calculation.
  struct Board {
    BN128.G1Point tmpl;
    BN128.G1Point tmpr;
    BN128.G1Point f;
    BN128.G1Point s;
    BN128.G1Point tmpgv;
    BN128.G1Point tmphv;

    uint index;
    uint[] challenges;
    uint[] challengesInverse;
  }

  struct CalResult {
    BN128.G1Point ue;
    BN128.G1Point np;

    IPProof proof;
  }


  /*
   * @dev verify inner product proof.
   * p[0-1]: p point.
   * scalar[0]: a.
   * scalar[1]: b.
   * scalar[2]: c.
   */
  function optimizedVerifyIPProof(uint[] memory gv, uint[] memory hv, uint[2] memory p, uint[2] memory u, uint c, uint[] memory l, uint[] memory r, uint a, uint b) public view returns(bool) {
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
  function verifyIPProof(uint[] memory gv, uint[] memory hv, uint[2] memory p, uint[2] memory u, uint c, uint[] memory l, uint[] memory r, uint a, uint b) public view returns(bool) {
    CalResult memory cal;
    bool valid;
    (valid, cal) = basicCheck(gv, hv, p, u, c, l, r, a, b);
    if (!valid) {
      return false;
    }

    return verifyIPProofNormal(gv, hv, cal.ue, cal.np, cal.proof);
  }

  function basicCheck(uint[] memory gv, uint[] memory hv, uint[2] memory p, uint[2] memory u, uint c, uint[] memory l, uint[] memory r, uint a, uint b) internal view returns(bool, CalResult memory) {
    // for simple check.
    CalResult memory cal;
    if (gv.length != hv.length || l.length != r.length) {
      return (false, cal);
    }

    if (2**(l.length/2) != gv.length/2) {
      return (false, cal);
    }
  
    
    cal.proof.l = new uint[](l.length);
    cal.proof.r = new uint[](l.length);
    for (uint i = 0; i < l.length; i++) {
      cal.proof.l[i] = l[i];
      cal.proof.r[i] = r[i];
    }

    cal.proof.a = a;
    cal.proof.b = b;

    // compute challenge e.
    uint e = computeChallengeStep1(c);

    cal.ue = BN128.G1Point(u[0], u[1]).mul(e);
    cal.np = cal.ue.mul(c).add(BN128.G1Point(p[0], p[1]));

    return (true, cal);
  }

  function verifyIPProofMulti(uint[] memory gv, uint[] memory hv, BN128.G1Point memory newU, BN128.G1Point memory p, IPProof memory proof) internal view  returns(bool) {
    Board memory b;
    b.challenges = new uint[](proof.l.length/2);
    b.challengesInverse = new uint[](proof.l.length/2);
    // compute formula on the right.
    // compute p + li * xi^2 + ri * xi^-2.
    for (uint i = 0; i < proof.l.length/2; i++) {
      b.tmpl = BN128.G1Point(proof.l[2*i], proof.l[2*i+1]);
      b.tmpr = BN128.G1Point(proof.r[2*i], proof.r[2*i+1]);
      uint x = computeChallengeStep2(proof.l[2*i], proof.l[2*i+1], proof.r[2*i], proof.r[2*i+1]);
      uint xInverse = x.inv();
      b.challenges[i] = x;
      b.challengesInverse[i] = xInverse;
      p = p.add(b.tmpl.mul(x.mul(x))).add(b.tmpr.mul(xInverse.mul(xInverse)));
    }

    // compute formula on the left.
    // compute g*s*a + h*s^-1*b + u*a*b.

    // compute s.
    uint[] memory s = new uint[](gv.length/2);
    for (uint i = 0; i < gv.length/2; i++) {
      for (uint j = 0; j < proof.l.length/2; j++) {
        uint tmp;

        if (smallParseBinary(i, j, proof.l.length/2)) {
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
    left = multiExp(gv, s).mul(proof.a).add(multiExpInverse(hv, s).mul(proof.b)).add(newU.mul(proof.a.mul(proof.b)));

    return left.X == p.X && left.Y == p.Y;
  }

  
  function verifyIPProofNormal(uint[] memory gv, uint[] memory hv, BN128.G1Point memory newU, BN128.G1Point memory p, IPProof memory proof) internal view  returns(bool) {
    Board memory b;
    uint step = 2;

    for (uint i = 0; i < proof.l.length/2; i++) {
      b.tmpl = BN128.G1Point(proof.l[2*i], proof.l[2*i+1]);
      b.tmpr = BN128.G1Point(proof.r[2*i], proof.r[2*i+1]);
      uint e = computeChallengeStep2(proof.l[2*i], proof.l[2*i+1], proof.r[2*i], proof.r[2*i+1]);
      uint eInverse = e.inv();

      for (uint j = 0; j < gv.length/2/step; j++) {
        // compute gv prime.
        b.index = gv.length/2/step+j;
        b.f = BN128.G1Point(gv[2*j], gv[2*j+1]);
        b.s = BN128.G1Point(gv[b.index*2], gv[b.index*2+1]);
        
        b.tmpgv = b.f.mul(eInverse).add(b.s.mul(e));
        gv[j*2] = b.tmpgv.X;
        gv[j*2+1] = b.tmpgv.Y; 

        // compute hv prime.
        b.f = BN128.G1Point(hv[2*j], hv[2*j+1]);
        b.s = BN128.G1Point(hv[b.index*2], hv[b.index*2+1]);
        b.tmphv = b.f.mul(e).add(b.s.mul(eInverse));
        hv[j*2] = b.tmphv.X;
        hv[j*2+1] = b.tmphv.Y;
      }

      // compute p points.
      // p' = l*x^2 + r^*xInv^2 + p.
      p = b.tmpl.mul(e.mul(e).mod()).add(b.tmpr.mul(eInverse.mul(eInverse).mod())).add(p);

      step = step * 2;
    }

    // c = a * b;
    uint c = proof.a.mul(proof.b).mod();

    // want = gv[0]*a + hv[0]*b + u*c.
    b.f = BN128.G1Point(gv[0], gv[1]);
    b.s = BN128.G1Point(hv[0], hv[1]);
    BN128.G1Point memory want = newU.mul(c).add(b.f.mul(proof.a)).add(b.s.mul(proof.b));

    return p.X == want.X && p.Y == want.Y;
  }

  function computeChallengeStep1(uint a) internal pure returns(uint) {
    return uint(keccak256(abi.encodePacked(a))).mod();
  }

  function computeChallengeStep2(uint a, uint b, uint c, uint d) internal pure returns(uint) {
    return uint(keccak256(abi.encodePacked(a, b, c, d))).mod();
  }

  function smallParseBinary(uint t, uint j, uint size) internal pure returns(bool) {
    uint w = 1 << (size - 1);

    for (uint i = 0; i < j; i++) {
      w = w >> 1;
    }

    if ((t&w) != 0) {
      return true;
    }

    return false;
  }

  function multiExp(uint[] memory base, uint[] memory exp) internal view returns(BN128.G1Point memory) {
    BN128.G1Point memory res;
    res = BN128.G1Point(base[0], base[1]).mul(exp[0]);
    for (uint i = 1; i < exp.length; i++) {
      res = res.add(BN128.G1Point(base[2*i], base[2*i+1]).mul(exp[i]));
    }

    return res;
  }

  function multiExpInverse(uint[] memory base, uint[] memory exp) internal view returns(BN128.G1Point memory) {
    uint[] memory expInverse = new uint[](exp.length);
    for (uint i = 0; i < exp.length; i++) {
      expInverse[i] = exp[i].inv();
    }

    return multiExp(base, expInverse);
  }
}
