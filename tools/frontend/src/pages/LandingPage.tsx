import { Link } from "react-router-dom";

export function LandingPage() {
    return (
        <section className="card-grid">
            <div className="card">
                <h2>Organization Console</h2>
                <p>
                    Bootstrap roles, issue credential attestations, configure zero-knowledge verifiers, and manage
                    organization settings in one place.
                </p>
                <Link className="primary-button" to="/organization">
                    Manage Organization
                </Link>
            </div>
            <div className="card">
                <h2>User Portal</h2>
                <p>
                    Register an identity, update metadata, and inspect credential proofs that have been issued to your
                    account.
                </p>
                <Link className="secondary-button" to="/user">
                    Enter User Portal
                </Link>
            </div>
        </section>
    );
}
