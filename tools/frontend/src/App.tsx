import { Suspense } from "react";
import { Navigate, Route, Routes } from "react-router-dom";

import { AppLayout } from "./components/AppLayout";
import { WalletProvider } from "./contexts/WalletProvider";
import { LandingPage } from "./pages/LandingPage";
import { OrganizationDashboard } from "./pages/OrganizationDashboard";
import { UserDashboard } from "./pages/UserDashboard";

export default function App() {
    return (
        <WalletProvider>
            <AppLayout>
                <Suspense fallback={<div className="loader">Loading…</div>}>
                    <Routes>
                        <Route path="/" element={<LandingPage />} />
                        <Route path="/organization" element={<OrganizationDashboard />} />
                        <Route path="/user" element={<UserDashboard />} />
                        <Route path="*" element={<Navigate to="/" replace />} />
                    </Routes>
                </Suspense>
            </AppLayout>
        </WalletProvider>
    );
}
