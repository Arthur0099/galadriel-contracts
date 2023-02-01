pragma solidity >=0.4.21 <0.6.0;

import "./library/SafeMath.sol";

/**
 * @title Roles
 * @dev Library for managing addresses assigned to a Role.
 */
library Roles {
    struct Role {
        mapping (address => bool) bearer;
    }

    /**
     * @dev Give an account access to this role.
     */
    function add(Role storage role, address account) internal {
        require(!has(role, account), "Roles: account already has role");
        role.bearer[account] = true;
    }

    /**
     * @dev Remove an account's access to this role.
     */
    function remove(Role storage role, address account) internal {
        require(has(role, account), "Roles: account does not have role");
        role.bearer[account] = false;
    }

    /**
     * @dev Check if an account has this role.
     * @return bool
     */
    function has(Role storage role, address account) internal view returns (bool) {
        require(account != address(0), "Roles: account is the zero address");
        return role.bearer[account];
    }
}

/**
 * @title WhitelistAdminRole
 * @dev WhitelistAdmins are responsible for assigning and removing Whitelisted accounts.
 */
contract WhitelistAdminRole {
    using Roles for Roles.Role;

    event WhitelistAdminAdded(address indexed account);
    event WhitelistAdminRemoved(address indexed account);

    Roles.Role private _whitelistAdmins;

    constructor () internal {
        _addWhitelistAdmin(msg.sender);
    }

    modifier onlyWhitelistAdmin() {
        require(isWhitelistAdmin(msg.sender), "WhitelistAdminRole: caller does not have the WhitelistAdmin role");
        _;
    }

    function isWhitelistAdmin(address account) public view returns (bool) {
        return _whitelistAdmins.has(account);
    }

    function addWhitelistAdmin(address account) public onlyWhitelistAdmin {
        _addWhitelistAdmin(account);
    }

    function renounceWhitelistAdmin() public {
        _removeWhitelistAdmin(msg.sender);
    }

    function _addWhitelistAdmin(address account) internal {
        _whitelistAdmins.add(account);
        emit WhitelistAdminAdded(account);
    }

    function _removeWhitelistAdmin(address account) internal {
        _whitelistAdmins.remove(account);
        emit WhitelistAdminRemoved(account);
    }
}

/**
 * @title WhitelistedRole
 * @dev Whitelisted accounts have been approved by a WhitelistAdmin to perform certain actions (e.g. participate in a
 * crowdsale). This role is special in that the only accounts that can add it are WhitelistAdmins (who can also remove
 * it), and not Whitelisteds themselves.
 */
contract WhitelistedRole is WhitelistAdminRole {
    using Roles for Roles.Role;

    event WhitelistedAdded(address indexed account);
    event WhitelistedRemoved(address indexed account);

    Roles.Role private _whitelisteds;

    modifier onlyWhitelisted() {
        require(isWhitelisted(msg.sender), "WhitelistedRole: caller does not have the Whitelisted role");
        _;
    }

    constructor() public {
      _addWhitelisted(msg.sender);
    }

    function isWhitelisted(address account) public view returns (bool) {
        return _whitelisteds.has(account);
    }

    function addWhitelisted(address account) public onlyWhitelistAdmin {
        _addWhitelisted(account);
    }

    function removeWhitelisted(address account) public onlyWhitelistAdmin {
        _removeWhitelisted(account);
    }

    function renounceWhitelisted() public {
        _removeWhitelisted(msg.sender);
    }

    function _addWhitelisted(address account) internal {
        _whitelisteds.add(account);
        emit WhitelistedAdded(account);
    }

    function _removeWhitelisted(address account) internal {
        _whitelisteds.remove(account);
        emit WhitelistedRemoved(account);
    }
}

contract TokenConverter is WhitelistedRole {

  using SafeMath for uint;

  struct Token {
    string name;
    // added or not.
    bool added;
    // 1 pgc => amount of this token.
    // Warning: be careful with decimal with ether and token. i. e. 1 pgc == 1 ether means 1 gpc == 10**18.
    uint precision;
  }

  mapping(address => Token) tokens;

  constructor() public {
    Token memory etherToken;
    etherToken.name = "ether";
    etherToken.added = true;

    uint decimal = 2;
    uint rate = 10**decimal;
    etherToken.precision = 1 ether / rate;

    // set token address (0) as ether.
    tokens[address(0)] = etherToken;
  }


  /*
   *
   */
  function addToken(address token, uint precision, string memory name) public onlyWhitelisted returns(bool) {
    require(uint(token) != 0, "invalid token address");
    require(!tokens[token].added, "token already added");
    require(precision > 0, "invalid precision");

    tokens[token].added = true;
    tokens[token].precision = precision;
    tokens[token].name = name;

    return true;
  }

  /*
   * @dev convert token amount to pgc amount.
   */
  function convertToPGC(address tokenAddr, uint tokenAmount) public view returns(uint) {
    Token memory token = tokens[tokenAddr];
    require(tokenAmount > 0, "amount can't be zero");
    require(token.added, "token not support currently");
    require(token.precision >= 1, "token's precision not set right");
    require(tokenAmount.div(token.precision).mul(token.precision) == tokenAmount, "invalid amount precision");

    return tokenAmount.div(token.precision);
  }

  /*
   * @dev convert pgc amount to token amount.
   */
  function convertToToken(address tokenAddr, uint pgcAmount) public view returns(uint) {
    Token memory token = tokens[tokenAddr];
    require(pgcAmount > 0, "pgc amount can't be zero");
    require(token.added, "token not support currently");
    require(token.precision >= 1, "token's precision not set right");

    return pgcAmount.mul(token.precision);
  }

  /*
   *
   */
  function getTokenInfo(address tokenAddr) public view returns(bool, string memory, uint) {
    return (tokens[tokenAddr].added, tokens[tokenAddr].name, tokens[tokenAddr].precision);
  }
}
