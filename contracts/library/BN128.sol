pragma solidity ^0.7.0;

library BN128 {
    // uint256 public constant q = 21888242871839275222246405745257275088548364400416034343698204186575808495617; // curve order
    // uint256 public constant n = 21888242871839275222246405745257275088696311157297823662689037894645226208583; // prime field order
    // uint256 public constant b = 3;

    // uint256 constant public ECSignMask = 0x8000000000000000000000000000000000000000000000000000000000000000;
    // uint256 constant public BigModExponent = (n + 1)/4;

    struct G1Point {
        uint256 X;
        uint256 Y;
    }

    function add(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint256[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        assembly {
            if iszero(staticcall(not(0), 6, input, 0x80, r, 0x40)) {
                revert(0, 0)
            }
        }
    }

    // function add(uint256[2] p1, uint256[2] p2) internal view returns (uint256[2] r) {
    //     uint256[4] memory input;
    //     input[0] = p1[0];
    //     input[1] = p1[1];
    //     input[2] = p2[0];
    //     input[3] = p2[1];
    //     assembly {
    //         if iszero(staticcall(not(0), 6, input, 0x80, r, 0x40)) {
    //             revert(0, 0)
    //         }
    //     }
    // }

    // function mul(uint256[2] P, uint256 s) internal view returns (uint256[2] R) {
    //     uint256[3] memory input;
    //     input[0] = P[0];
    //     input[1] = P[1];
    //     input[2] = s;
    //     assembly {
    //         if iszero(staticcall(not(0), 7, input, 0x60, R, 0x40)) {
    //             revert(0, 0)
    //         }
    //     }
    // }

    function mul(G1Point memory p, uint256 s) internal view returns (G1Point memory r) {
        if (s == 1) {
            return p;
        }
        if (s == 2) {
            return add(p, p);
        }
        uint256[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        assembly {
            if iszero(staticcall(not(0), 7, input, 0x60, r, 0x40)) {
                revert(0, 0)
            }
        }
    }

    function neg(G1Point memory p) internal pure returns (G1Point memory) {
        if (p.X == 0 && p.Y == 0) return G1Point(0, 0);
        uint256 n = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        return G1Point(p.X, n - p.Y);
        // return G1Point(p.X, n - (p.Y % n));
    }

    function eq(G1Point memory p1, G1Point memory p2) internal pure returns (bool) {
        return p1.X == p2.X && p1.Y == p2.Y;
    }

    function add(uint256 x, uint256 y) internal pure returns (uint256) {
        uint256 q = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        return addmod(x, y, q);
    }

    function mul(uint256 x, uint256 y) internal pure returns (uint256) {
        uint256 q = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        return mulmod(x, y, q);
    }

    // function inv2(uint256 x) internal view returns (uint256) {
    //     uint256 q = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    //     return modExp(x, q - 2, q);
    // }

    function inv(uint256 x) internal pure returns (uint256) {
        uint256 p = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        uint256 a = x;
        if (a == 0) return 0;
        if (a > p) a = a % p;
        int256 t1;
        int256 t2 = 1;
        uint256 r1 = p;
        uint256 r2 = a;
        uint256 q;
        while (r2 != 0) {
            q = r1 / r2;
            (t1, t2, r1, r2) = (t2, t1 - int256(q) * t2, r2, r1 - q * r2);
        }
        if (t1 < 0) return (p - uint256(-t1));
        return uint256(t1);
    }

    function mod(uint256 x) internal pure returns (uint256) {
        uint256 q = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        return x % q;
    }

    function sub(uint256 x, uint256 y) internal pure returns (uint256) {
        uint256 q = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        return x >= y ? x - y : q - y + x;
    }

    function neg(uint256 x) internal pure returns (uint256) {
        return 21888242871839275222246405745257275088548364400416034343698204186575808495617 - x;
    }

    function modExp(
        uint256 base,
        uint256 exponent,
        uint256 modulus
    ) internal view returns (uint256) {
        uint256[6] memory input;
        uint256[1] memory output;
        input[0] = 0x20; // length_of_BASE
        input[1] = 0x20; // length_of_EXPONENT
        input[2] = 0x20; // length_of_MODULUS
        input[3] = base;
        input[4] = exponent;
        input[5] = modulus;
        assembly {
            if iszero(staticcall(not(0), 5, input, 0xc0, output, 0x20)) {
                revert(0, 0)
            }
        }
        return output[0];
    }

    function modExp(uint256 base, uint256 exponent) internal view returns (uint256) {
        uint256 q = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        return modExp(base, exponent, q);
    }

    function decompressMulti(bytes memory input) internal view returns (G1Point[] memory out) {
        require(input.length % 33 == 0, 'invalid multi compressed point format');
        uint256 ln = input.length / 33;

        out = new G1Point[](ln);
        for (uint256 i = 0; i < ln; i++) {
            (bool ybit, uint256 x) = splitCompressedBytesToNormal(input, i);
            out[i] = xToPoint(x, ybit);
        }

        return out;
    }

    function decompress(bytes memory input) internal view returns (G1Point memory) {
        if (input.length != 33) {
            revert('invalid compressed point format');
        }
        (bool ybit, uint256 x) = splitCompressedBytesToNormal(input, 0);

        return xToPoint(x, ybit);
    }

    function xToPoint(uint256 x, bool ybit) internal view returns (G1Point memory out) {
        // zero point
        if (x == 0) return G1Point(0, 0);
        uint256 p = 21888242871839275222246405745257275088696311157297823662689037894645226208583;

        uint256 xxx = mulmod(x, x, p);
        xxx = mulmod(xxx, x, p);
        uint256 b = 3;
        uint256 y2 = addmod(xxx, b, p);

        uint256 y = modExp(y2, (p + 1) / 4, p);
        if (mulmod(y, y, p) != y2) {
            revert('Invalid point: not on curve');
        }

        out = G1Point(x, y);
        bool isOdd = y & 0x1 == 0x1;
        if (ybit != isOdd) {
            out = neg(out);
        }

        return out;
    }

    // bs length should be 33 * n
    // ln is the index of point
    function splitCompressedBytesToNormal(bytes memory bs, uint256 ln) internal pure returns (bool, uint256) {
        bool ybit = (uint8(bs[ln * 33]) & 0x1) == uint8(0x1);
        // skip the first bit
        uint256 x = bytesToUint256(bs, ln * 33 + 1);
        return (ybit, x);
    }

    function bytesToUint256(bytes memory bs, uint256 start) internal pure returns (uint256) {
        uint256 x;
        assembly {
            x := mload(add(bs, add(0x20, start)))
        }
        return x;
    }

    function hashToCurve(bytes memory input) internal view returns (G1Point memory p) {
        uint256 seed = uint256(keccak256(input));
        return uintToCurvePoint(seed);
    }

    function uintToCurvePoint(uint256 x) internal view returns (G1Point memory p) {
        uint256 n = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        uint256 seed = x % n;
        uint256 y;
        seed -= 1;
        bool onCurve = false;
        uint256 y2;
        uint256 b = uint256(3);
        while (!onCurve) {
            seed += 1;
            y2 = mulmod(seed, seed, n);
            y2 = mulmod(y2, seed, n);
            y2 = addmod(y2, b, n);
            // y2 += b;
            y = modExp(y2, (n + 1) / 4, n);
            onCurve = mulmod(y, y, n) == y2;
        }
        return G1Point(seed, y);
    }
}
