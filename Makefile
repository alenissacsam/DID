include .env

install:
	@forge install cyfrin/foundry-devops
	@forge install smartcontractkit/chainlink-brownie-contracts
	@forge install openzeppelin/openzeppelin-contracts

deploy-nexus:
	@forge script script/deploy.s.sol:DeployAll --via-ir --broadcast \
	--rpc-url ${NEXUS_RPC_URL} --private-key ${NEXUS_KEY} \
	--verify --verifier blockscout --verifier-url ${NEXUS_VERIFIER} -vv

deploy-polygon:

deploy-sepolia:
	@forge script script/DeployEduCertCoreContracts.s.sol:DeployEduCertCoreContracts --via-ir --broadcast \
	--rpc-url https://sepolia.drpc.org --private-key --legacy -vv
