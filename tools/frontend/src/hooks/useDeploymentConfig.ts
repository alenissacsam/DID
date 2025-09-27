import { useQuery } from "@tanstack/react-query";
import { z } from "zod";

const RawConfigSchema = z.object({
    network: z.object({
        chainId: z.union([z.number(), z.string().transform((val) => Number(val))]),
        name: z.string(),
    }),
    deployer: z
        .object({
            address: z.string().optional(),
        })
        .optional(),
    core: z.record(z.string(), z.string()).optional(),
    verification: z.record(z.string(), z.string()).optional(),
    identity: z.record(z.string(), z.string()).optional(),
    organizations: z.record(z.string(), z.string()).optional(),
    governance: z.record(z.string(), z.string()).optional(),
    zk: z
        .object({
            manager: z.string().optional(),
            verifiers: z.record(z.string(), z.string()).optional(),
        })
        .optional(),
    meta: z.record(z.string(), z.string()).optional(),
});

export type DeploymentConfig = {
    chainId: number;
    networkName: string;
    contracts: Record<string, string>;
    raw: z.infer<typeof RawConfigSchema>;
};

function normalizeConfig(raw: z.infer<typeof RawConfigSchema>): DeploymentConfig {
    const sections: Array<Record<string, string> | undefined> = [
        raw.core,
        raw.verification,
        raw.identity,
        raw.organizations,
        raw.governance,
        raw.zk?.verifiers,
    ];
    const contracts: Record<string, string> = {};
    sections.forEach((section) => {
        if (!section) return;
        for (const [key, value] of Object.entries(section)) {
            contracts[key] = value;
        }
    });
    if (raw.zk?.manager) {
        contracts.zkProofManager = raw.zk.manager;
    }
    return {
        chainId: Number(raw.network.chainId),
        networkName: raw.network.name,
        contracts,
        raw,
    };
}

async function fetchConfig(path: string): Promise<DeploymentConfig | null> {
    const response = await fetch(path, { cache: "no-cache" });
    if (!response.ok) {
        return null;
    }
    const json = await response.json();
    const raw = RawConfigSchema.parse(json);
    return normalizeConfig(raw);
}

export function useDeploymentConfig() {
    return useQuery({
        queryKey: ["deployment-config"],
        queryFn: async () => {
            const liveConfig = await fetchConfig("/config/deployment.json");
            if (liveConfig) return liveConfig;

            const sampleConfig = await fetchConfig("/config/deployment.sample.json");
            if (sampleConfig) return sampleConfig;

            throw new Error("Deployment config not found. Ensure deploy script outputs deployment.json");
        },
        staleTime: 1000 * 60 * 5,
        retry: 1,
    });
}
