import Link from "next/link";
import { useEffect, useState } from "react";

import { apiGet } from "../lib/apiClient";

type BootstrapResponse = {
  session_id: string;
  current_layer: number;
};

export default function Home() {
  const [data, setData] = useState<BootstrapResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiGet<BootstrapResponse>("/api/session/bootstrap")
      .then(setData)
      .catch((err) => setError(String(err)));
  }, []);

  return (
    <main style={{ maxWidth: 760, margin: "40px auto", fontFamily: "sans-serif" }}>
      <h1>PROJECT: NULL</h1>
      <p>Session-bound 30-layer initiation challenge.</p>

      {error && <p style={{ color: "crimson" }}>{error}</p>}
      {!data && !error && <p>Bootstrapping session...</p>}

      {data && (
        <>
          <p>Session: {data.session_id}</p>
          <p>Current Layer: {data.current_layer}</p>
          <p>
            <Link href={`/dossier/${data.current_layer}`}>Open current dossier layer</Link>
          </p>
          <p>
            <Link href="/finalize">Finalize</Link>
          </p>
        </>
      )}
    </main>
  );
}
