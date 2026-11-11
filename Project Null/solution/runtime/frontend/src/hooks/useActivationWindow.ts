import { useEffect, useMemo, useState } from "react";

export function useActivationWindow(expiresAtIso?: string) {
  const [now, setNow] = useState<number>(Date.now());

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  return useMemo(() => {
    if (!expiresAtIso) {
      return { secondsRemaining: 0, expired: true };
    }

    const target = new Date(expiresAtIso).getTime();
    const secondsRemaining = Math.max(0, Math.floor((target - now) / 1000));
    return {
      secondsRemaining,
      expired: secondsRemaining === 0,
    };
  }, [expiresAtIso, now]);
}
