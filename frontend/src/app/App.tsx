import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { createBrowserRouter, RouterProvider } from "react-router-dom";
import { ToastProvider, TooltipProvider } from "@/components/ui";
import { ApiError } from "@/lib/api";
import { AuthProvider } from "@/features/auth/AuthProvider";
import { ROUTER_FUTURE, routeTree } from "./routeTree";

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      staleTime: 15_000,
      refetchOnWindowFocus: false,
      retry: (count, error) => !(error instanceof ApiError && [401, 403, 404, 422].includes(error.status)) && count < 2,
    },
  },
});

const router = createBrowserRouter(routeTree, { future: ROUTER_FUTURE });

export function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <ToastProvider>
          <AuthProvider>
            <RouterProvider router={router} future={{ v7_startTransition: true }} />
          </AuthProvider>
        </ToastProvider>
      </TooltipProvider>
    </QueryClientProvider>
  );
}
