import { render, screen } from "@testing-library/react";
import { Markdown } from "../markdown/Markdown";
import { parseInline, parseMarkdown, safeHref } from "../markdown/parse";

describe("Markdown — HTML injection", () => {
  it("renders raw HTML as text and never creates elements from it", () => {
    const { container } = render(
      <Markdown source={'<script>alert(1)</script>\n\n<img src=x onerror="alert(2)">\n\n**<b onclick="x()">bold</b>**'} />,
    );
    expect(container.querySelector("script")).toBeNull();
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("b")).toBeNull();
    expect(container.querySelector("[onerror]")).toBeNull();
    expect(container.querySelector("[onclick]")).toBeNull();
    expect(container.textContent).toContain("<script>alert(1)</script>");
    expect(container.textContent).toContain('<img src=x onerror="alert(2)">');
  });

  it("drops javascript:, data: and relative link targets but keeps the text", () => {
    const { container } = render(
      <Markdown source={"[click](javascript:alert(1)) [d](data:text/html,<script>x</script>) [rel](/admin) [js2]( JAVASCRIPT:alert(1))"} />,
    );
    expect(container.querySelectorAll("a")).toHaveLength(0);
    expect(container.textContent).toContain("click");
    expect(container.textContent).toContain("rel");
  });

  it("renders http(s) links in a new tab with rel=noopener", () => {
    render(<Markdown source="See [the docs](https://example.com/guide?x=1) or https://example.org/path." />);
    const docs = screen.getByRole("link", { name: "the docs" });
    expect(docs).toHaveAttribute("href", "https://example.com/guide?x=1");
    expect(docs).toHaveAttribute("target", "_blank");
    expect(docs.getAttribute("rel")).toContain("noopener");
    const bare = screen.getByRole("link", { name: "https://example.org/path" });
    expect(bare).toHaveAttribute("href", "https://example.org/path");
  });

  it("does not let code fences or inline code execute or render HTML", () => {
    const { container } = render(<Markdown source={"Use `<iframe src=x>` here.\n\n```html\n<script>evil()</script>\n```"} />);
    expect(container.querySelector("iframe")).toBeNull();
    expect(container.querySelector("script")).toBeNull();
    expect(screen.getByText("<iframe src=x>").tagName).toBe("CODE");
    expect(screen.getByText("html")).toBeInTheDocument();
    expect(container.querySelector("pre")?.textContent).toBe("<script>evil()</script>");
  });
});

describe("Markdown — structure", () => {
  it("offsets headings below the page heading", () => {
    render(<Markdown source={"# Summary\n\n## Steps"} />);
    expect(screen.getByRole("heading", { level: 2, name: "Summary" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 3, name: "Steps" })).toBeInTheDocument();
  });

  it("parses nested and ordered lists and task items", () => {
    const blocks = parseMarkdown("1. First\n2. Second\n   - nested a\n   - nested b\n\n- [x] done\n- [ ] todo");
    expect(blocks).toHaveLength(2);
    const ordered = blocks[0];
    expect(ordered.type === "list" && ordered.ordered && ordered.items.length).toBe(2);
    if (ordered.type === "list") {
      const nested = ordered.items[1].children.find((b) => b.type === "list");
      expect(nested && nested.type === "list" && nested.items.length).toBe(2);
    }
    const tasks = blocks[1];
    expect(tasks.type === "list" && tasks.items.map((i) => i.checked)).toEqual([true, false]);
  });

  it("keeps snake_case identifiers and arithmetic literal", () => {
    expect(parseInline("tool_invocation_id and 2 * 3 * 4")).toEqual([{ type: "text", value: "tool_invocation_id and 2 * 3 * 4" }]);
    expect(parseInline("**bold** and *em* and _em2_")).toEqual([
      { type: "strong", children: [{ type: "text", value: "bold" }] },
      { type: "text", value: " and " },
      { type: "em", children: [{ type: "text", value: "em" }] },
      { type: "text", value: " and " },
      { type: "em", children: [{ type: "text", value: "em2" }] },
    ]);
  });

  it("supports escapes, blockquotes and thematic breaks", () => {
    const { container } = render(<Markdown source={"\\*not em\\*\n\n> quoted **text**\n\n---"} />);
    expect(container.querySelector("em")).toBeNull();
    expect(container.textContent).toContain("*not em*");
    expect(container.querySelector("blockquote strong")?.textContent).toBe("text");
    expect(container.querySelector("hr")).not.toBeNull();
  });

  it("handles fences inside list items, unclosed fences, hard breaks and nested emphasis", () => {
    const blocks = parseMarkdown("- step one\n\n  ```bash\n  pytest -q\n  ```\n- step two\n\n```\nunclosed");
    expect(blocks[0].type).toBe("list");
    if (blocks[0].type === "list") {
      expect(blocks[0].items[0].children.map((b) => b.type)).toEqual(["paragraph", "code"]);
      const code = blocks[0].items[0].children[1];
      expect(code.type === "code" && code.value).toBe("pytest -q");
    }
    expect(blocks[1]).toEqual({ type: "code", lang: null, value: "unclosed" });
    expect(parseMarkdown("line one  \nline two")[0]).toEqual({
      type: "paragraph",
      children: [{ type: "text", value: "line one" }, { type: "break" }, { type: "text", value: "line two" }],
    });
    expect(parseInline("***both***")).toEqual([{ type: "strong", children: [{ type: "em", children: [{ type: "text", value: "both" }] }] }]);
  });

  it("never nests anchors and keeps balanced parentheses in URLs", () => {
    const { container } = render(<Markdown source="[https://a.example](https://b.example/wiki/Foo_(bar))" />);
    const anchors = container.querySelectorAll("a");
    expect(anchors).toHaveLength(1);
    expect(anchors[0]).toHaveAttribute("href", "https://b.example/wiki/Foo_(bar)");
    expect(anchors[0].querySelector("a")).toBeNull();
  });

  it("highlights redaction markers inside text", () => {
    const { container } = render(<Markdown source="Key was [REDACTED:aws_access_key:1a2b3c4d] in the file." />);
    const marker = container.querySelector('[data-redacted="true"]');
    expect(marker?.textContent).toBe("[REDACTED:aws_access_key:1a2b3c4d]");
  });
});

describe("safeHref", () => {
  it.each([
    ["https://example.com", "https://example.com/"],
    ["http://localhost:8000/x", "http://localhost:8000/x"],
    ["javascript:alert(1)", null],
    ["  javascript:alert(1)", null],
    ["data:text/html,hi", null],
    ["/relative", null],
    ["//evil.example", null],
    ["vbscript:x", null],
  ])("%s → %s", (input, expected) => {
    expect(safeHref(input)).toBe(expected);
  });
});
