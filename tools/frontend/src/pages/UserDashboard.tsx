import { useWallet } from "../contexts/WalletProvider";
import { useDeploymentConfig } from "../hooks/useDeploymentConfig";

export function UserDashboard() {
    const { data, isLoading, error } = useDeploymentConfig();
    const { account } = useWallet();

    if (isLoading) {
        return <p className="status-message">Loading deployment configuration…</p>;
    }

    if (error) {
        return <p className="status-message error">{(error as Error).message}</p>;
    }

    if (!data) {
        return <p className="status-message">No deployment data available.</p>;
    }

    return (
        <section className="stack gap-lg">
            <header className="section-header">
                <div>
                    <h2>User Portal</h2>
                    <p className="section-subtitle">
                        Connected as <strong>{account ?? "No wallet connected"}</strong>
                    </p>
                </div>
            </header>

            <div className="card">
                <h3>Available Credential Contracts</h3>
                <p className="section-subtitle">
                    The following contracts are available for credential issuance and verification. Use your wallet to
                    request attestations or prove attributes.
                </p>
                <ul className="address-list">
                    {Object.entries(data.contracts).map(([name, address]) => (
                        <li key={name}>
                            <span className="contract-name">{name}</span>
                            <span className="address-chip">{address}</span>
                        </li>
                    ))}
                </ul>
            </div>

            <div className="card">
                <h3>Next Steps for Users</h3>
                <ol className="ordered-actions">
                    <li>Register your identity using the IdentityManager contract.</li>
                    <li>Request credentials from whitelisted organization issuers.</li>
                    <li>Store the deployment config for offline verification of zero-knowledge proofs.</li>
                </ol>
            </div>
        </section>
    );
}
