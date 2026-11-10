import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createBrowserRouter, Navigate, Outlet, RouterProvider, useLocation } from "react-router-dom";
import { AppShell } from "@/components/layout/AppShell";
import { ToastProvider, TooltipProvider, LoadingRows } from "@/components/ui";
import { ApiError } from "@/lib/api";
import { AuthProvider, useAuth } from "@/features/auth/AuthProvider";
import { LoginPage } from "@/features/auth/LoginPage";
import { NotFoundPage } from "@/features/auth/NotFoundPage";
import { appRoutes } from "./routes";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 15_000,
      refetchOnWindowFocus: false,
      retry: (count, error) => !(error instanceof ApiError && [401, 403, 404, 422].includes(error.status)) && count < 2,
    },
  },
});

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
  if (!me) return <Navigate to="/login" replace state={{ from: location.pathname }} />;
  return <Outlet />;
}

const router = createBrowserRouter([
  { path: "/login", element: <LoginPage /> },
  {
    element: <RequireAuth />,
    children: [{ path: "/", element: <AppShell />, children: [...appRoutes, { path: "*", element: <NotFoundPage /> }] }],
  },
]);

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <ToastProvider>
          <AuthProvider>
            <RouterProvider router={router} />
          </AuthProvider>
        </ToastProvider>
      </TooltipProvider>
    </QueryClientProvider>
  );
}
