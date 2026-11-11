import { useRouter } from "next/router";
import { FormEvent, useEffect, useState } from "react";

import { useActivationWindow } from "../../hooks/useActivationWindow";
import { apiGet, apiPost } from "../../lib/apiClient";

type LayerResponse = {
  layer: number;
  id: string;
  title: string;
  act: number;
  timer_seconds: number;
  public_asset: string;
  unlocked: boolean;
};

type ActivateResponse = {
  activation_token: string;
  expires_in_seconds: number;
  expires_at: string;
};

type SubmitResponse = {
  status: "correct" | "incorrect" | "false_positive";
  fragment: string | null;
  current_layer: number;
  final_ready: boolean;
};

export default function DossierLayerPage() {
  const router = useRouter();
  const layerNumber = Number(router.query.layer);

  const [layer, setLayer] = useState<LayerResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [keyValue, setKeyValue] = useState("");
  const [activation, setActivation] = useState<ActivateResponse | null>(null);
  const [result, setResult] = useState<SubmitResponse | null>(null);

  const { secondsRemaining, expired } = useActivationWindow(activation?.expires_at);

  useEffect(() => {
    if (!Number.isFinite(layerNumber)) return;
    apiGet<LayerResponse>(`/api/layer/${layerNumber}`)
      .then(setLayer)
      .catch((err) => setError(String(err)));
  }, [layerNumber]);

  async function onActivate() {
    if (!layer) return;
    setError(null);
    setResult(null);
    try {
      const payload = await apiPost<ActivateResponse>(`/api/layer/${layer.layer}/activate`, {});
      setActivation(payload);
    } catch (err) {
      setError(String(err));
    }
  }

  async function onSubmit(event: FormEvent) {
    event.preventDefault();
    if (!layer || !activation) return;
    setError(null);
    try {
      const payload = await apiPost<SubmitResponse>("/api/submit-layer", {
        layer: layer.layer,
        key: keyValue,
        activation_token: activation.activation_token,
      });
      setResult(payload);
      if (payload.status === "correct" && payload.current_layer !== layer.layer) {
        router.push(`/dossier/${payload.current_layer}`);
      }
    } catch (err) {
      setError(String(err));
    }
  }

  return (
    <main style={{ maxWidth: 760, margin: "40px auto", fontFamily: "sans-serif" }}>
      <h1>Dossier Layer {Number.isFinite(layerNumber) ? layerNumber : "?"}</h1>

      {error && <p style={{ color: "crimson" }}>{error}</p>}
      {!layer && !error && <p>Loading layer...</p>}

      {layer && (
        <>
          <h2>{layer.title}</h2>
          <p>Act: {layer.act}</p>
          <p>
            Public Asset: <a href={layer.public_asset}>{layer.public_asset}</a>
          </p>

          <button onClick={onActivate}>Activate Window</button>
          {activation && <p>Window remaining: {secondsRemaining}s</p>}

          <form onSubmit={onSubmit} style={{ marginTop: 16 }}>
            <input
              value={keyValue}
              onChange={(e) => setKeyValue(e.target.value)}
              placeholder="submit key"
              style={{ minWidth: 300 }}
            />
            <button disabled={!activation || expired || !keyValue} type="submit">
              Submit
            </button>
          </form>

          {result && (
            <div style={{ marginTop: 16 }}>
              <p>Status: {result.status}</p>
              <p>Fragment: {result.fragment ?? "none"}</p>
              <p>Current Layer: {result.current_layer}</p>
              <p>Final Ready: {String(result.final_ready)}</p>
            </div>
          )}
        </>
      )}
    </main>
  );
}
