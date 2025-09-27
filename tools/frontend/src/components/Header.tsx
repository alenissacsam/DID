import { useWallet } from "../contexts/WalletProvider";

export function Header() {
    const { account, connect, disconnect, isConnecting } = useWallet();

    return (
        <header className="app-header">
            <div>
                <h1 className="app-title">Modular Identity Console</h1>
                <p className="app-subtitle">Deploy, manage, and verify decentralized credentials.</p>
            </div>
            <button
                className="primary-button"
                onClick={account ? disconnect : connect}
                disabled={isConnecting}
            >
                {account ? `Disconnect ${shortAddress(account)}` : isConnecting ? "Connecting..." : "Connect Wallet"}
            </button>
        </header>
    );
}

function shortAddress(address: string) {
    return `${address.slice(0, 6)}…${address.slice(-4)}`;
}
