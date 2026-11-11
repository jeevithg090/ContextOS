/**
 * The application route tree: sign-in, the authenticated shell, every page (src/app/routes.tsx),
 * the 404 page and the error boundaries. Kept apart from App.tsx so tests can mount it in a
 * memory router.
 */
import { Navigate, Outlet, useLocation, type RouteObject } from "react-router-dom";
import { AppShell } from "@/components/layout/AppShell";
import { LoadingRows } from "@/components/ui";
import { useAuth } from "@/features/auth/AuthProvider";
import { LoginPage } from "@/features/auth/LoginPage";
import { NotFoundPage } from "@/features/auth/NotFoundPage";
import { RouteError } from "./RouteError";
import { RouteTitle } from "./RouteTitle";
import { appRoutes, type RouteHandle } from "./routes";

function RequireAuth() {
  const { me, loading } = useAuth();
  const location = useLocation();
  if (loading) {
    return (
      <div className="mx-auto max-w-md pt-32">
        <LoadingRows rows={3} />
      </div>
    );
  }
  if (!me) return <Navigate to="/login" replace state={{ from: location.pathname + location.search }} />;
  return <Outlet />;
}

/** Root layout: names the browser tab after the matched route. */
function Root() {
  return (
    <>
      <RouteTitle />
      <Outlet />
    </>
  );
}

const notFound: RouteHandle = { title: "Page not found" };
const signIn: RouteHandle = { title: "Sign in" };

export const routeTree: RouteObject[] = [
  {
    element: <Root />,
    // Last-resort boundary (errors in the shell itself or on the sign-in page).
    errorElement: <RouteError />,
    children: [
      { path: "/login", element: <LoginPage />, handle: signIn },
      {
        element: <RequireAuth />,
        children: [
          {
            path: "/",
            element: <AppShell />,
            children: [
              // Page-level boundary: a failing page renders its error inside the shell, so the
              // navigation keeps working.
              { errorElement: <RouteError />, children: [...appRoutes, { path: "*", element: <NotFoundPage />, handle: notFound }] },
            ],
          },
        ],
      },
    ],
  },
];

/** React Router v7 behaviour, opted into now (also silences the v6 deprecation warnings). */
export const ROUTER_FUTURE = {
  v7_relativeSplatPath: true,
  v7_fetcherPersist: true,
  v7_normalizeFormMethod: true,
  v7_partialHydration: true,
  v7_skipActionErrorRevalidation: true,
} as const;
