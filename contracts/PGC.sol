pragma solidity >=0.5.0 <0.6.0;

import './library/BN128.sol';
import './PublicParams.sol';
import './TokenConverter.sol';
import './Verifier.sol';

/**
 * @dev Interface of the ERC20 standard as defined in the EIP. Does not include
 * the optional functions; to access them see `ERC20Detailed`.
 */
interface IERC20 {
    /**
     * @dev Moves `amount` tokens from the caller's account to `recipient`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a `Transfer` event.
     */
    function transfer(address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Moves `amount` tokens from `sender` to `recipient` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a `Transfer` event.
     */
    function transferFrom(
        address sender,
        address recipient,
        uint256 amount
    ) external returns (bool);
}

contract PGC {
    using BN128 for BN128.G1Point;
    using BN128 for uint256;
    using BN128 for bytes;

    // encrypted ct.(balance of account)
    struct CT {
        BN128.G1Point X;
        BN128.G1Point Y;
        uint256 nonce;
    }

    //
    struct Board {
        // for tmp calculation.
        CT ct1;
        CT ct2;
        CT tmpUpdatedBalance;
        address token;
        uint256 tokenAmount;
        uint256 pgcAmount;
        //
        uint256[4] userBalance;
        uint256 localNonce;
        // for log event.
        uint256[4] fromto;
        uint256[4] logCt1;
        uint256[4] logCt2;
        uint256[8] aggCT;
    }

    // pk.x => pk.y => uint(address) => ct encrypt current balance.
    mapping(uint256 => mapping(uint256 => mapping(uint256 => CT))) currentBalance;
    // pk.x => pk.y => uint(address) => ct encrypt last balance.
    // balnce not roll over into current balance but can be spent.
    // nonce not set in this ct.
    mapping(uint256 => mapping(uint256 => mapping(uint256 => CT))) lastBalance;

    // pk.x => pk.y => uint(address) => ct encrypt pending balance.
    // balance in current epoch and can't be spent.
    mapping(uint256 => mapping(uint256 => mapping(uint256 => CT))) pendingBalance;

    // pk.x => pk.y => epochLength. number fo block one epoch contains.
    // epoch = block.number / epochLength;
    mapping(uint256 => mapping(uint256 => uint256)) epochLength;

    // pk.x => pk.y => uint(address) => lastRolloverEpoch;
    // the epoch of last out tx of user in token.
    // currentEpoch = currentblock.number / epoch
    // epoch between currentEpoch and last rollover epoch is last epoch.
    mapping(uint256 => mapping(uint256 => mapping(uint256 => uint256))) lastRolloverEpoch;

    // pk.x => pk.y => uint(address) => lastPendingEpoch;
    mapping(uint256 => mapping(uint256 => mapping(uint256 => uint256))) lastPendingEpoch;

    // pk.x => pk.y => bool.
    // pending status open or not.
    mapping(uint256 => mapping(uint256 => bool)) pendingOpened;

    // pk.x => pk.y => uint.
    mapping(uint256 => mapping(uint256 => uint256)) pendingFunNonce;

    // bitSize of balance value.
    uint256 public constant bitSize = 32;
    uint256 public constant n = 5;
    uint256 public constant maxNumber = 2**bitSize;
    // 2^step = aggSize
    uint256 constant step = 1;
    // proof l, r size.
    uint256 constant lrSize = n + step;

    // public h point.
    BN128.G1Point public h;

    // public g point.
    BN128.G1Point public g;

    // params.
    PublicParams public params;

    // token converter.
    TokenConverter public tokenConverter;

    // proof verifier.
    Verifier public verifier;

    // events
    event LogDepositAccount(
        address indexed proxy,
        address indexed token,
        uint256 tox,
        uint256 toy,
        uint256 amount,
        uint256 time
    );
    event LogAggTransfer(address indexed proxy, address indexed token, uint256[4] fromto, uint256[8] ct, uint256 time);
    event LogTransfer(
        address indexed proxy,
        address indexed token,
        uint256[4] fromto,
        uint256[4] ct1,
        uint256[4] ct2,
        uint256 time
    );
    event LogBurn(
        address indexed proxy,
        address indexed receiver,
        address indexed token,
        uint256 accountx,
        uint256 accounty,
        uint256 amount,
        uint256 time
    );
    event LogBurnPart(
        address indexed proxy,
        address indexed receiver,
        address indexed token,
        uint256 accountx,
        uint256 accounty,
        uint256 amount,
        uint256 time
    );

    // constructor.
    constructor(
        address params_,
        address verifier_,
        address tokenConverter_
    ) public {
        verifier = Verifier(verifier_);
        tokenConverter = TokenConverter(tokenConverter_);
        params = PublicParams(params_);

        uint256[2] memory tmpH = params.getH();
        uint256[2] memory tmpG = params.getG();

        h.X = tmpH[0];
        h.Y = tmpH[1];
        g.X = tmpG[0];
        g.Y = tmpG[1];
        require(bitSize == params.getBitSize(), 'bitsize not equal');
    }

    // pgc account open the capacity of pending state.
    // the incoming tx will be set to pending state not to current state directly.
    function openPending(
        uint256 x,
        uint256 y,
        uint256 epochLength_,
        uint256 nonce,
        uint256[2] memory sig
    ) public {
        require(!pendingOpened[x][y], 'pending already opened');
        uint256 localNonce = pendingFunNonce[x][y];
        require(nonce == localNonce, 'invalid nonce');
        // verify sig.
        uint256 hash = uint256(keccak256(abi.encodePacked(x, y, epochLength_, nonce))).mod();
        require(verifySig(hash, x, y, sig[0], sig[1]), 'verify open pending sig failed');

        // epoch length can't below 5.
        if (epochLength_ < 5) {
            // set default epoch length value.
            epochLength_ = 50;
        }

        epochLength[x][y] = epochLength_;
        pendingOpened[x][y] = true;
        pendingFunNonce[x][y] = localNonce.add(1);
    }

    // pgc account close the capacity of pending state.
    function closePending(
        uint256 x,
        uint256 y,
        uint256 nonce,
        uint256[2] memory sig
    ) public {
        require(pendingOpened[x][y], 'pending already closed');
        uint256 localNonce = pendingFunNonce[x][y];
        require(nonce == localNonce, 'invalid nonce');
        // verify sig.
        uint256 hash = uint256(keccak256(abi.encodePacked(x, y, nonce))).mod();
        require(verifySig(hash, x, y, sig[0], sig[1]), 'verify close pending sig failed');

        epochLength[x][y] = 0;
        pendingOpened[x][y] = false;
        pendingFunNonce[x][y] = localNonce.add(1);
    }

    // toPoint, only for test
    function toPoint(bytes memory bs) public view returns (uint256[] memory, uint256[] memory) {
        BN128.G1Point[] memory ps = bs.decompressMulti();

        uint256[] memory x = new uint256[](ps.length);
        uint256[] memory y = new uint256[](ps.length);
        for (uint256 i = 0; i < ps.length; i++) {
            x[i] = ps[i].X;
            y[i] = ps[i].Y;
        }

        return (x, y);
    }

    function depositAccountETH(bytes memory publicKey) public payable returns (bool) {
        depositAccount(publicKey, address(0), 0);
    }

    /*
     * @dev deposit eth to an account.
     * randomness is always set to zero. a depositer don't need to know the privatekey of pgc amount.
     */
    function depositAccount(
        bytes memory publicKey,
        address tokenAddr,
        uint256 tokenAmount
    ) public payable returns (bool) {
        uint256 pgcAmount;
        if (uint256(tokenAddr) == 0) {
            // use msg.value to calculate amount instead.
            pgcAmount = tokenConverter.convertToPGC(tokenAddr, msg.value);
        } else {
            require(msg.value == 0, "deposit token don't receive eth");

            // transfer token to this contract.
            require(IERC20(tokenAddr).transferFrom(msg.sender, address(this), tokenAmount), 'token transfer failed');
            pgcAmount = tokenConverter.convertToPGC(tokenAddr, tokenAmount);
        }
        // encrypt amount and pending it.
        BN128.G1Point memory pk = publicKey.decompress();
        CT memory pb = encrypt(pgcAmount, pk);
        toBalanceOrPending(pb, pk.X, pk.Y, uint256(tokenAddr));

        emit LogDepositAccount(msg.sender, tokenAddr, pk.X, pk.Y, pgcAmount, now);

        return true;
    }

    function aggTransferETH(
        bytes memory points,
        uint256[10] memory scalar,
        bytes memory lr
    ) public returns (bool) {
        aggTransfer(points, scalar, 0, lr);
    }

    /*
   * 0: points[0-1]: pk1
   * 1: points[2-3]: pk2
   * 2: points[4-5]: ct x1
   * 3: points[6-7]: ct x2
   * 4: points[8-9]: ct x3
   * 5: points[10-11]: ct y
   * 6: points[12-13]: pte A1
   * 7: points[14-15]: pte A2
   * 8: points[16-17]: pte A3
   * 9: points[14-15]: pte B
   * 10: points[20-21]: pk1's refreshed balance ct.X
   * 11: points[22-23]: pk1's refreshed balance ct.Y
   * 12: points[24-25]: ct valid proof A
   * 13: points[26-27]: ct valid proof B
   * 14: points[28-29]: dle eq proof A1.
   * 15: points[30-31]: dle eq proof A2.
   * 16: points[32-33]: agg range proof A.
   * 17: points[34-35]: agg range proof S.
   * 18: points[36-37]: agg range proof T1.
   * 19: points[38-39]: agg range proof T2.

   * scalar[0]: pte proof z1.
   * scalar[1]: pte proof z2.
   * scalar[2]: ct valid z1.
   * scalar[3]: ct valid z2. 
   * scalar[4]: dloge proof Z.
   * scalar[5]: agg range proof t.
   * scalar[6]: agg range proof tx.
   * scalar[7]: agg range proof u.
   * scalar[8]: agg range proof a.
   * scalar[9]: agg range proof b.

   * l[0-11]: agg range proof l.x, l.y.
   * r[0-11]: agg range proof r.x, r.y.
   */
    function aggTransfer(
        bytes memory points,
        uint256[10] memory scalar,
        uint256 token,
        bytes memory lr
    ) public returns (bool) {
        require(points.length == 33 * 20, 'Invalid points length');
        require(lr.length == 33 * 2 * lrSize, 'Invalid lr length');

        Board memory b;
        // nonce used for computing hash. no need to check.

        // decompress points
        BN128.G1Point[] memory ps = points.decompressMulti();

        // 2 add if no pending.
        b.ct1.X = ps[2];
        b.ct1.Y = ps[5];
        b.tmpUpdatedBalance = getBalanceCanSpentInternal(ps[0].X, ps[0].Y, token);
        b.tmpUpdatedBalance.X = b.tmpUpdatedBalance.X.add(b.ct1.X.neg());
        b.tmpUpdatedBalance.Y = b.tmpUpdatedBalance.Y.add(b.ct1.Y.neg());

        uint256[4] memory updated;
        updated[0] = b.tmpUpdatedBalance.X.X;
        updated[1] = b.tmpUpdatedBalance.X.Y;
        updated[2] = b.tmpUpdatedBalance.Y.X;
        updated[3] = b.tmpUpdatedBalance.Y.Y;
        // check proof.
        require(
            verifier.verify(points, scalar, lr, updated, b.tmpUpdatedBalance.nonce, token),
            'transfer proofs invalid'
        );

        // update sender's balance.
        // 4 add.
        rolloverAndUpdate(b.tmpUpdatedBalance, ps[0].X, ps[0].Y, token);

        // update receiver balance or make it to pending.
        b.ct2.X = ps[3];
        b.ct2.Y = ps[5];
        toBalanceOrPending(b.ct2, ps[1].X, ps[1].Y, token);

        // set for event.
        b.fromto[0] = ps[0].X;
        b.fromto[1] = ps[0].Y;
        b.fromto[2] = ps[1].X;
        b.fromto[3] = ps[1].Y;
        b.aggCT[0] = ps[2].X;
        b.aggCT[1] = ps[2].Y;
        b.aggCT[2] = ps[3].X;
        b.aggCT[3] = ps[3].Y;
        b.aggCT[4] = ps[4].X;
        b.aggCT[5] = ps[4].Y;
        b.aggCT[6] = ps[5].X;
        b.aggCT[7] = ps[5].Y;
        emit LogAggTransfer(msg.sender, address(token), b.fromto, b.aggCT, now);

        return true;
    }

    function getUserBalance(
        uint256 x,
        uint256 y,
        address token
    ) public view returns (uint256[4] memory ct, uint256 nonce) {
        CT memory userBalance = getBalanceCanSpentInternal(x, y, uint256(token));
        ct[0] = userBalance.X.X;
        ct[1] = userBalance.X.Y;
        ct[2] = userBalance.Y.X;
        ct[3] = userBalance.Y.Y;
        nonce = userBalance.nonce;
        return (ct, nonce);
    }

    function getPendingFunNonce(uint256 x, uint256 y) public view returns (uint256) {
        return pendingFunNonce[x][y];
    }

    function burnETH(
        address payable receiver,
        uint256 amount,
        // pk, A1, A2
        bytes memory points,
        uint256 z
    ) public returns (bool) {
        burn(receiver, 0, amount, points, z);
    }

    /*
     * @dev burn withdraw all eth back to eth account.
     * pk
     * proof[0-1]: A1 point.
     * proof[2-3]: A2 point.
     *
     */
    function burn(
        address payable receiver,
        uint256 token,
        uint256 amount,
        // pk, A1, A2
        bytes memory points,
        uint256 z
    ) public returns (bool) {
        // do nothing
        require(amount >= 1, 'invalid amount');

        BN128.G1Point[] memory ps = points.decompressMulti();

        // check proof.
        uint256[4] memory userBalance;
        uint256 nonceSent;
        (userBalance, nonceSent) = getUserBalance(ps[0].X, ps[0].Y, address(token));
        // revert when error.

        uint256[] memory input = new uint256[](3);
        input[0] = nonceSent;
        input[1] = uint256(receiver);
        input[2] = token;
        // receiver, nonce, token used for computing hash
        require(verifier.verifyBurn(amount, points, z, userBalance, input), 'dle sigma verify failed');

        // update user encrypted balance.
        CT memory tmpUpdatedBalance;
        tmpUpdatedBalance.X = BN128.G1Point(0, 0);
        tmpUpdatedBalance.Y = BN128.G1Point(0, 0);
        tmpUpdatedBalance.nonce = nonceSent;
        rolloverAndUpdate(tmpUpdatedBalance, ps[0].X, ps[0].Y, token);

        if (token == 0) {
            // transfer eth back to user.
            receiver.transfer(tokenConverter.convertToToken(address(token), amount));
        } else {
            require(
                IERC20(address(token)).transfer(receiver, tokenConverter.convertToToken(address(token), amount)),
                'transfer token back to user failed'
            );
        }

        emit LogBurn(msg.sender, receiver, address(token), ps[0].X, ps[1].Y, amount, now);
    }

    /*
     * @dev encrypt for despoit eth account. the randomness is set to 0.
     * @dev it's ok since the eth amount is public know to everyone.
     * @dev but the ctx's randomness is not know.
     */
    function encrypt(uint256 amount, BN128.G1Point memory pk) internal view returns (CT memory) {
        require(amount < 2**bitSize, 'amount out of range');

        // no sense.
        // r = 0;

        CT memory ct;
        // X = pk * r.
        // cause r is set to 0.
        ct.X = BN128.G1Point(0, 0);
        // Y = g*m + h*r.
        ct.Y = g.mul(amount);

        return ct;
    }

    /*
     * @dev 4 mul, 1 add.
     */
    function verifySig(
        uint256 hash,
        uint256 pkx,
        uint256 pky,
        uint256 r,
        uint256 s
    ) internal view returns (bool) {
        s = s.inv();
        uint256 u1 = hash.mul(s);
        uint256 u2 = r.mul(s);
        BN128.G1Point memory res = h.mul(u1).add(BN128.G1Point(pkx, pky).mul(u2));
        if (res.X != r) {
            return false;
        }
        return true;
    }

    /*
     * @dev return balance can be spent by public key and token address.
     */
    function getBalanceCanSpentInternal(
        uint256 x,
        uint256 y,
        uint256 token
    ) internal view returns (CT memory) {
        // add currentBalance and lastBalance not matter whether pending status
        // open or not since lastBalance will be set to zero when closed except
        // the first out tx after close. but it's right to add the balance since it doesn't be spent.
        CT memory cb = currentBalance[x][y][token];
        CT memory lb = lastBalance[x][y][token];
        CT memory fb;
        fb.nonce = cb.nonce;
        fb.X = cb.X.add(lb.X);
        fb.Y = cb.Y.add(lb.Y);

        // first tx after close pending capacity.
        // todo:
        if (!pendingOpened[x][y] && pendingBalance[x][y][token].Y.X != 0) {
            // will be set to zero.
            fb.X = fb.X.add(pendingBalance[x][y][token].X);
            fb.Y = fb.Y.add(pendingBalance[x][y][token].Y);
        }

        // no in tx changes pending balance to last balance in epoch.
        if (
            pendingOpened[x][y] &&
            pendingBalance[x][y][token].Y.X != 0 &&
            block.number / epochLength[x][y] > lastPendingEpoch[x][y][token]
        ) {
            fb.X = fb.X.add(pendingBalance[x][y][token].X);
            fb.Y = fb.Y.add(pendingBalance[x][y][token].Y);
        }

        return fb;
    }

    /*
     * @dev reduce balance of user's balance and rollover user's pending state.
     * @dev even epoch is current epoch, also rollover it.
     * @dev call before any out tx.
     */
    function rolloverAndUpdate(
        CT memory balance,
        uint256 x,
        uint256 y,
        uint256 token
    ) internal {
        currentBalance[x][y][token] = balance;
        currentBalance[x][y][token].nonce = balance.nonce.add(1);

        // set last balance to zero. already be calculated.
        if (lastBalance[x][y][token].Y.X != 0) {
            lastBalance[x][y][token].X = BN128.G1Point(0, 0);
            lastBalance[x][y][token].Y = BN128.G1Point(0, 0);
        }

        // set pending balance to zero if pending not opened.
        if (!pendingOpened[x][y] && pendingBalance[x][y][token].Y.X != 0) {
            pendingBalance[x][y][token].X = BN128.G1Point(0, 0);
            pendingBalance[x][y][token].Y = BN128.G1Point(0, 0);
        }

        // first out tx in epoch.
        // no need to check lastPendingEpoch is zero or not. any in tx will update it. and without in tx, one just send any out tx.
        if (pendingOpened[x][y] && block.number / epochLength[x][y] > lastPendingEpoch[x][y][token]) {
            lastPendingEpoch[x][y][token] = block.number / epochLength[x][y];

            // this can be spent, so set it to zero.
            if (pendingBalance[x][y][token].Y.X != 0) {
                pendingBalance[x][y][token].X = BN128.G1Point(0, 0);
                pendingBalance[x][y][token].Y = BN128.G1Point(0, 0);
            }
        }
    }

    /*
     * @dev add balance to user' balance or pending.
     */
    function toBalanceOrPending(
        CT memory balance,
        uint256 x,
        uint256 y,
        uint256 token
    ) internal {
        // not open pending capacity.
        if (!pendingOpened[x][y]) {
            CT storage cb = currentBalance[x][y][token];
            cb.X = cb.X.add(balance.X);
            cb.Y = cb.Y.add(balance.Y);

            // at this point, the last balance and pending balance may not zero, but it will be calculated when user burn/transfer.

            return;
        }

        CT storage lb = lastBalance[x][y][token];
        CT storage pb = pendingBalance[x][y][token];
        // try to pending this tx.
        uint256 currentEpoch = block.number / epochLength[x][y];
        // just pending ct to pending state.
        if (currentEpoch == lastPendingEpoch[x][y][token]) {
            pb.X = pb.X.add(balance.X);
            pb.Y = pb.Y.add(balance.Y);

            return;
        }

        // currentEpoch is bigger than last pending epoch. so just add pending balance to last balance and set pending balance to ct.
        // currentEpoch always >= lastpendingepoch.
        lb.X = lb.X.add(pb.X);
        lb.Y = lb.Y.add(pb.Y);
        // reset pending state.
        pb.X = balance.X;
        pb.Y = balance.Y;
        // reset last pending epoch.
        lastPendingEpoch[x][y][token] = currentEpoch;
    }
}
