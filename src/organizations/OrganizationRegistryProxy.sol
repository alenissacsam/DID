// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./OrganizationLogic.sol";
import "./OrganizationView.sol";

contract OrganizationRegistryProxy is OrganizationLogic, OrganizationView {
    constructor(address certificateManager_, address trustScore_, address verificationLogger_)
        OrganizationLogic(certificateManager_, trustScore_, verificationLogger_)
    {}
}
