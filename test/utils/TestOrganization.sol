// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {OrganizationLogic} from "src/organizations/OrganizationLogic.sol";

contract TestOrganization is OrganizationLogic {
    constructor(
        address cert,
        address trust,
        address logger
    ) OrganizationLogic(cert, trust, logger) {}
}
