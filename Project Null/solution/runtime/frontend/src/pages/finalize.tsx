import { FormEvent, useState } from "react";

import { apiPost } from "../lib/apiClient";

type FinalizeResponse = {
  status: string;
  message: string;
};

export default function FinalizePage() {
  const [flagValue, setFlagValue] = useState("");
  const [result, setResult] = useState<FinalizeResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    setError(null);
    try {
      const payload = await apiPost<FinalizeResponse>("/api/finalize", {
        final_flag: flagValue,
      });
      setResult(payload);
    } catch (err) {
      setError(String(err));
    }
  }

  return (
    <main style={{ maxWidth: 760, margin: "40px auto", fontFamily: "sans-serif" }}>
      <h1>Finalize Session</h1>
      <form onSubmit={onSubmit}>
        <input
          value={flagValue}
          onChange={(e) => setFlagValue(e.target.value)}
          placeholder="zerosec{...}"
          style={{ minWidth: 360 }}
        />
        <button type="submit" disabled={!flagValue}>
          Submit Final Flag
        </button>
      </form>

      {error && <p style={{ color: "crimson" }}>{error}</p>}
      {result && (
        <div>
          <p>Status: {result.status}</p>
          <p>Message: {result.message}</p>
        </div>
      )}
    </main>
  );
}
