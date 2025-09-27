import type { InterfaceAbi } from "ethers";
import { BrowserProvider, Contract, ContractRunner, Interface, JsonRpcSigner } from "ethers";

import { DeploymentConfig } from "../hooks/useDeploymentConfig";

type AbiInput = Interface | InterfaceAbi;

export function getContractInstance(
    config: DeploymentConfig,
    contractName: string,
    runner: BrowserProvider | JsonRpcSigner,
    abi: AbiInput | undefined
) {
    const address = config.contracts[contractName];
    if (!address) {
        throw new Error(`Contract ${contractName} not present in deployment config`);
    }
    if (!abi) {
        throw new Error(
            `ABI required to instantiate ${contractName}. Pass an ABI or extend deployment config with abi metadata.`
        );
    }

    const contractRunner: ContractRunner = runner instanceof BrowserProvider ? runner : runner;
    return new Contract(address, abi, contractRunner);
}

export function assertNetworkMatch(config: DeploymentConfig, chainId: number | null) {
    if (!chainId) return;
    if (config.chainId !== chainId) {
        throw new Error(
            `Connected chainId (${chainId}) does not match deployment config chainId (${config.chainId}).`
        );
    }
}
