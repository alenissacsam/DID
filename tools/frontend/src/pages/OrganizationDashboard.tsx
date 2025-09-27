import { useMemo } from "react";

import { useWallet } from "../contexts/WalletProvider";
import { useDeploymentConfig } from "../hooks/useDeploymentConfig";
import { assertNetworkMatch } from "../services/contractService";

export function OrganizationDashboard() {
    const { data, isLoading, error } = useDeploymentConfig();
    const { chainId, account } = useWallet();

    const deploymentSummary = useMemo(() => {
        if (!data) return [];
        return Object.entries(data.contracts).map(([name, address]) => ({ name, address }));
    }, [data]);

    if (isLoading) {
        return <p className="status-message">Loading deployment configuration…</p>;
    }

    if (error) {
        return <p className="status-message error">{(error as Error).message}</p>;
    }

    if (!data) {
        return <p className="status-message">No deployment data available.</p>;
    }

    try {
        assertNetworkMatch(data, chainId);
    } catch (networkError) {
        return <p className="status-message warning">{(networkError as Error).message}</p>;
    }

    return (
        <section className="stack gap-lg">
            <header className="section-header">
                <div>
                    <h2>Organization Dashboard</h2>
                    <p className="section-subtitle">
                        Connected as <strong>{account ?? "No wallet connected"}</strong>
                    </p>
                </div>
            </header>

            <div className="card">
                <h3>Deployment Summary</h3>
                <ul className="address-list">
                    {deploymentSummary.map((item) => (
                        <li key={item.name}>
                            <span className="contract-name">{item.name}</span>
                            <span className="address-chip">{item.address}</span>
                        </li>
                    ))}
                </ul>
            </div>

            <div className="card">
                <h3>Next Actions</h3>
                <ol className="ordered-actions">
                    <li>Assign roles to organization admins using the deployed AccessManager.</li>
                    <li>Issue ZK verifiers for each credential attribute your organization supports.</li>
                    <li>Review broadcast artifacts to verify transaction hashes and block numbers.</li>
                </ol>
            </div>
        </section>
    );
}
