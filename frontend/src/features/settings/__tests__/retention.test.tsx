import { render, screen } from "@testing-library/react";
import { RetentionScope } from "../RetentionScope";

describe("RetentionScope", () => {
  it("says the purge command deletes data, what it deletes and what it keeps", () => {
    render(<RetentionScope days={90} />);
    expect(screen.getByText("contextos-server purge")).toBeInTheDocument();
    expect(screen.getByText(/recorded more than 90 days earlier/)).toBeInTheDocument();
    expect(screen.getByText(/open and acknowledged findings are never purged/)).toBeInTheDocument();
    expect(screen.getByText(/The audit log: it is a hash chain/)).toBeInTheDocument();
    expect(screen.getByText(/Evidence of open, investigating or contained incidents/)).toBeInTheDocument();
    expect(screen.queryByText(/automatically/)).not.toBeInTheDocument();
  });

  it("omits the day count while the entered value is invalid", () => {
    render(<RetentionScope days={null} />);
    expect(screen.queryByText(/days earlier/)).not.toBeInTheDocument();
  });
});
