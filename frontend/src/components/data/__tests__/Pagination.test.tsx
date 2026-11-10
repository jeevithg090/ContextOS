import { act, fireEvent, render, renderHook, screen } from "@testing-library/react";
import { Pagination } from "../Pagination";
import { usePagination } from "@/hooks/usePagination";

describe("Pagination", () => {
  it("shows the visible range and page position", () => {
    render(<Pagination total={312} limit={25} offset={25} onChange={() => {}} itemLabel="findings" />);
    const nav = screen.getByRole("navigation", { name: "Pagination" });
    expect(nav).toHaveTextContent("26–50 of 312 findings");
    expect(nav).toHaveTextContent("Page 2 of 13");
  });

  it("disables previous controls on the first page and next controls on the last", () => {
    const { rerender } = render(<Pagination total={60} limit={25} offset={0} onChange={() => {}} />);
    expect(screen.getByRole("button", { name: "Previous page" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "First page" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Next page" })).toBeEnabled();

    rerender(<Pagination total={60} limit={25} offset={50} onChange={() => {}} />);
    expect(screen.getByRole("navigation")).toHaveTextContent("51–60 of 60");
    expect(screen.getByRole("button", { name: "Next page" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Last page" })).toBeDisabled();
    expect(screen.getByRole("button", { name: "Previous page" })).toBeEnabled();
  });

  it("emits offsets for each control", () => {
    const onChange = vi.fn();
    render(<Pagination total={130} limit={25} offset={50} onChange={onChange} />);
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    fireEvent.click(screen.getByRole("button", { name: "Previous page" }));
    fireEvent.click(screen.getByRole("button", { name: "First page" }));
    fireEvent.click(screen.getByRole("button", { name: "Last page" }));
    expect(onChange.mock.calls.map((c) => c[0])).toEqual([75, 25, 0, 125]);
  });

  it("renders nothing for an empty result set", () => {
    const { container } = render(<Pagination total={0} limit={25} offset={0} onChange={() => {}} />);
    expect(container).toBeEmptyDOMElement();
  });

  it("offers a page-size selector when onLimitChange is provided", () => {
    const onLimitChange = vi.fn();
    render(<Pagination total={500} limit={25} offset={0} onChange={() => {}} onLimitChange={onLimitChange} />);
    fireEvent.change(screen.getByLabelText("Rows"), { target: { value: "100" } });
    expect(onLimitChange).toHaveBeenCalledWith(100);
  });
});

describe("usePagination", () => {
  it("tracks offset, resets, and returns to page one when the limit changes", () => {
    const { result } = renderHook(() => usePagination(25));
    expect(result.current.params).toEqual({ limit: 25, offset: 0 });
    act(() => result.current.setOffset(50));
    expect(result.current.params).toEqual({ limit: 25, offset: 50 });
    act(() => result.current.setOffset(-10));
    expect(result.current.offset).toBe(0);
    act(() => result.current.setOffset(75));
    act(() => result.current.setLimit(100));
    expect(result.current.params).toEqual({ limit: 100, offset: 0 });
    act(() => result.current.setOffset(200));
    act(() => result.current.reset());
    expect(result.current.offset).toBe(0);
  });
});
