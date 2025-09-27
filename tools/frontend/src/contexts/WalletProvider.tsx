import { BrowserProvider, Eip1193Provider, JsonRpcSigner } from "ethers";
import type { ReactNode } from "react";
import { createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";

export type WalletContextValue = {
    account: string | null;
    chainId: number | null;
    provider: BrowserProvider | null;
    signer: JsonRpcSigner | null;
    connect: () => Promise<void>;
    disconnect: () => void;
    isConnecting: boolean;
};

const WalletContext = createContext<WalletContextValue | undefined>(undefined);

type EventfulProvider = Eip1193Provider & {
    on?: (eventName: string, listener: (...args: unknown[]) => void) => void;
    removeListener?: (eventName: string, listener: (...args: unknown[]) => void) => void;
};

function getInjectedProvider(): Eip1193Provider | undefined {
    if (typeof window !== "undefined" && window.ethereum) {
        return window.ethereum;
    }
    return undefined;
}

export function WalletProvider({ children }: { children: ReactNode }) {
    const [account, setAccount] = useState<string | null>(null);
    const [chainId, setChainId] = useState<number | null>(null);
    const [provider, setProvider] = useState<BrowserProvider | null>(null);
    const [signer, setSigner] = useState<JsonRpcSigner | null>(null);
    const [isConnecting, setIsConnecting] = useState(false);

    const connect = useCallback(async () => {
        const injected = getInjectedProvider();
        if (!injected) {
            throw new Error("No injected wallet found. Install MetaMask or another provider.");
        }
        setIsConnecting(true);
        try {
            const browserProvider = new BrowserProvider(injected, "any");
            const accounts = await browserProvider.send("eth_requestAccounts", []);
            const signerInstance = await browserProvider.getSigner();
            const network = await browserProvider.getNetwork();
            setAccount(accounts[0]);
            setChainId(Number(network.chainId));
            setProvider(browserProvider);
            setSigner(signerInstance);
        } finally {
            setIsConnecting(false);
        }
    }, []);

    const disconnect = useCallback(() => {
        setAccount(null);
        setChainId(null);
        setProvider(null);
        setSigner(null);
    }, []);

    useEffect(() => {
        const injected = getInjectedProvider();
        if (!injected) return;

        function handleAccountsChanged(accounts: string[]) {
            setAccount(accounts.length > 0 ? accounts[0] : null);
        }
        function handleChainChanged(hexChainId: string) {
            setChainId(parseInt(hexChainId, 16));
        }

        const eventful = injected as EventfulProvider;

        eventful.on?.("accountsChanged", handleAccountsChanged);
        eventful.on?.("chainChanged", handleChainChanged);

        return () => {
            eventful.removeListener?.("accountsChanged", handleAccountsChanged);
            eventful.removeListener?.("chainChanged", handleChainChanged);
        };
    }, []);

    const value = useMemo(
        () => ({ account, chainId, provider, signer, connect, disconnect, isConnecting }),
        [account, chainId, provider, signer, connect, disconnect, isConnecting]
    );

    return <WalletContext.Provider value={value}>{children}</WalletContext.Provider>;
}

export function useWallet(): WalletContextValue {
    const ctx = useContext(WalletContext);
    if (!ctx) {
        throw new Error("useWallet must be used within WalletProvider");
    }
    return ctx;
}
