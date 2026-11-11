import { render, screen } from "@testing-library/react";
import { RiskMeter } from "../RiskMeter";

/**
 * The risk level is computed only by the server (backend/app/engines/risk/session.py
 * LEVEL_THRESHOLDS = 75/50/25). The meter used to derive a level from the score with its own,
 * different thresholds (80/60/30) whenever a caller omitted `level`.
 */
describe("RiskMeter", () => {
  it("shows the server's level, never one derived from the score", () => {
    render(<RiskMeter score={76} level="critical" showLevel label="Session risk" />);
    const meter = screen.getByRole("meter", { name: "Session risk" });
    expect(meter).toHaveAttribute("aria-valuenow", "76");
    expect(meter).toHaveAttribute("aria-valuetext", "76 out of 100, critical risk");
    expect(meter).toHaveTextContent("Critical");
  });

  it("draws a neutral meter without a level instead of guessing one", () => {
    render(<RiskMeter score={76} showLevel label="Session risk" />);
    const meter = screen.getByRole("meter", { name: "Session risk" });
    expect(meter).toHaveAttribute("aria-valuetext", "76 out of 100");
    expect(meter).not.toHaveTextContent(/critical|high|medium|low/i);
    expect(meter.querySelector(".text-fg-muted")).not.toBeNull();
  });

  it("ignores an unknown level and clamps the score", () => {
    render(<RiskMeter score={140} level="catastrophic" label="Risk" />);
    const meter = screen.getByRole("meter", { name: "Risk" });
    expect(meter).toHaveAttribute("aria-valuenow", "100");
    expect(meter).toHaveAttribute("aria-valuetext", "100 out of 100");
  });
});
