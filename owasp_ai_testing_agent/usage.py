"""Daily token ledger and cost alert (plan section 9: cost_alert_threshold €5/day).

Prices are NOT built in: model prices change and cannot be verified from here. Set
OWASP_AI_AGENT_PRICE_IN_EUR_PER_MTOK and OWASP_AI_AGENT_PRICE_OUT_EUR_PER_MTOK (euro per million
input / output tokens) to enable the euro estimate and alert. Without them, tokens are still logged
and the agent says once that the cost alert is off.
"""
from __future__ import annotations

import json
import sys
import threading
from datetime import date
from pathlib import Path

from .config import Config


class CostLimitExceeded(RuntimeError):
    pass


class UsageLedger:
    def __init__(self, config: Config):
        self.config = config
        self.path = Path(config.usage_file)
        self._lock = threading.Lock()
        self._warned_no_prices = False
        self._alerted = False

    @property
    def priced(self) -> bool:
        return self.config.price_in_eur_per_mtok is not None and self.config.price_out_eur_per_mtok is not None

    def _today(self) -> tuple[int, int]:
        tin = tout = 0
        if self.path.exists():
            today = date.today().isoformat()
            for line in self.path.read_text(encoding="utf-8").splitlines():
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if rec.get("date") == today:
                    tin += int(rec.get("input_tokens") or 0)
                    tout += int(rec.get("output_tokens") or 0)
        return tin, tout

    def cost_today_eur(self) -> float | None:
        if not self.priced:
            return None
        tin, tout = self._today()
        return tin / 1e6 * self.config.price_in_eur_per_mtok + tout / 1e6 * self.config.price_out_eur_per_mtok  # unrounded: small spend must still compare correctly

    def check_before_call(self) -> None:
        """Raise if today's spend already exceeds the threshold and a hard stop is configured."""
        cost = self.cost_today_eur()
        if cost is not None and self.config.cost_hard_stop and cost >= self.config.cost_alert_threshold_eur:
            raise CostLimitExceeded(f"today's estimated spend €{cost:.2f} has reached the €{self.config.cost_alert_threshold_eur:.2f} "
                                    "limit (OWASP_AI_AGENT_HARD_STOP is set)")

    def record(self, model: str, input_tokens: int | None, output_tokens: int | None) -> str | None:
        """Append usage; return an alert message if the daily estimate now exceeds the threshold."""
        with self._lock:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            with self.path.open("a", encoding="utf-8") as f:
                f.write(json.dumps({"date": date.today().isoformat(), "model": model,
                                    "input_tokens": input_tokens or 0, "output_tokens": output_tokens or 0}) + "\n")
            if not self.priced:
                if not self._warned_no_prices:
                    self._warned_no_prices = True
                    print("[usage] cost alert is off: set OWASP_AI_AGENT_PRICE_IN_EUR_PER_MTOK and "
                          "OWASP_AI_AGENT_PRICE_OUT_EUR_PER_MTOK to enable it", file=sys.stderr)
                return None
            cost = self.cost_today_eur()
            if cost is not None and cost >= self.config.cost_alert_threshold_eur and not self._alerted:
                self._alerted = True
                msg = f"estimated spend today €{cost:.2f} has reached the €{self.config.cost_alert_threshold_eur:.2f} alert threshold"
                print(f"[alert] {msg}", file=sys.stderr)
                return msg
        return None
