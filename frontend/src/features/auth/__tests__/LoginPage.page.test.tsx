import { fireEvent, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { currentLocation, errorReply, hang, makeMe, renderPage, serverError, stubApi, type ApiRoute, type Reply } from "@/test/pageHarness";
import { AuthProvider } from "../AuthProvider";
import { LoginPage } from "../LoginPage";

afterEach(() => vi.unstubAllGlobals());

/** Test-only credentials for the app's own sign-in form; never a real account. */
const EMAIL = "ada@acme.test";
const PASSWORD = "test-only-passphrase";

const ME = makeMe(["read", "write"]);
const SIGNED_OUT = errorReply(401, "not_authenticated", "Not signed in");

function routes({ setup, me = SIGNED_OUT, login, create }: { setup: Reply; me?: Reply; login?: Reply; create?: Reply }): ApiRoute {
  return (c) => {
    if (c.path === "/auth/me") return me;
    if (c.path === "/auth/setup-status") return setup;
    if (c.method === "POST" && c.path === "/auth/login") return login;
    if (c.method === "POST" && c.path === "/auth/setup") return create;
    return undefined;
  };
}

const renderLogin = () =>
  renderPage(
    <AuthProvider>
      <LoginPage />
    </AuthProvider>,
    { path: "/login", routePath: "/login" },
  );

function fill(label: string, value: string) {
  fireEvent.change(screen.getByLabelText(label), { target: { value } });
}

describe("LoginPage", () => {
  it("offers the sign-in form while the first-run check is still loading", () => {
    stubApi(routes({ setup: hang }));
    renderLogin();
    expect(screen.getByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.getByLabelText("Email")).toBeInTheDocument();
    expect(screen.queryByLabelText("Organisation name")).not.toBeInTheDocument();
  });

  it("says when the API cannot be reached", async () => {
    stubApi(routes({ setup: serverError() }));
    renderLogin();
    expect(await screen.findByText("Cannot reach the ContextOS API.")).toBeInTheDocument();
  });

  it("shows the server's message when sign-in is refused", async () => {
    const api = stubApi(routes({ setup: { body: { needs_setup: false } }, login: errorReply(401, "invalid_credentials", "Invalid email or password") }));
    renderLogin();
    fill("Email", EMAIL);
    fill("Password", PASSWORD);
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(await screen.findByRole("alert")).toHaveTextContent("Invalid email or password");
    expect(api.calls.find((c) => c.path === "/auth/login")?.body).toEqual({ email: EMAIL, password: PASSWORD });
    expect(currentLocation()).toBe("/login");
  });

  it("signs in and goes to the overview", async () => {
    stubApi(routes({ setup: { body: { needs_setup: false } }, login: { body: ME } }));
    renderLogin();
    fill("Email", EMAIL);
    fill("Password", PASSWORD);
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    await waitFor(() => expect(currentLocation()).toBe("/"));
  });

  it("creates the organisation and its owner on first run", async () => {
    const api = stubApi(routes({ setup: { body: { needs_setup: true } }, create: { status: 201, body: ME } }));
    renderLogin();
    expect(await screen.findByRole("heading", { name: "Create your organisation" })).toBeInTheDocument();
    expect(screen.getByText(/First run: this creates the organisation and its owner account/)).toBeInTheDocument();
    expect(screen.getByText("At least 10 characters.")).toBeInTheDocument();
    fill("Organisation name", "Acme Test Org");
    fill("Your name", "Ada Analyst");
    fill("Email", EMAIL);
    fill("Password", PASSWORD);
    fireEvent.click(screen.getByRole("button", { name: "Create organisation" }));
    await waitFor(() => expect(currentLocation()).toBe("/"));
    expect(api.calls.find((c) => c.path === "/auth/setup")?.body).toEqual({ organization_name: "Acme Test Org", name: "Ada Analyst", email: EMAIL, password: PASSWORD });
  });

  it("sends a signed-in user straight to the app", async () => {
    stubApi(routes({ setup: { body: { needs_setup: false } }, me: { body: ME } }));
    renderLogin();
    await waitFor(() => expect(currentLocation()).toBe("/"));
    expect(screen.queryByRole("heading", { name: "Sign in" })).not.toBeInTheDocument();
  });

  it("explains what is missing before sending anything", async () => {
    const api = stubApi(routes({ setup: { body: { needs_setup: false } } }));
    renderLogin();
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(screen.getByLabelText("Email")).toHaveAccessibleDescription("Enter your email address.");
    expect(screen.getByLabelText("Email")).toHaveFocus();
    expect(screen.getByLabelText("Password")).toHaveAttribute("aria-invalid", "true");
    fill("Email", "not-an-email");
    fill("Password", PASSWORD);
    fireEvent.click(screen.getByRole("button", { name: "Sign in" }));
    expect(screen.getByText("Enter a valid email address, like name@example.com.")).toBeInTheDocument();
    expect(api.calls.some((c) => c.path === "/auth/login")).toBe(false);
  });

  it("asks for a 10-character password when creating the organisation", async () => {
    const api = stubApi(routes({ setup: { body: { needs_setup: true } } }));
    renderLogin();
    await screen.findByRole("heading", { name: "Create your organisation" });
    fill("Organisation name", "Acme Test Org");
    fill("Your name", "Ada Analyst");
    fill("Email", EMAIL);
    fill("Password", "short");
    fireEvent.click(screen.getByRole("button", { name: "Create organisation" }));
    expect(screen.getByText("Use at least 10 characters.")).toBeInTheDocument();
    expect(api.calls.some((c) => c.path === "/auth/setup")).toBe(false);
  });

  it("can reveal the password", () => {
    stubApi(routes({ setup: { body: { needs_setup: false } } }));
    renderLogin();
    expect(screen.getByLabelText("Password")).toHaveAttribute("type", "password");
    fireEvent.click(screen.getByRole("button", { name: "Show password" }));
    expect(screen.getByLabelText("Password")).toHaveAttribute("type", "text");
    expect(screen.getByRole("button", { name: "Hide password" })).toHaveAttribute("aria-pressed", "true");
  });
});
