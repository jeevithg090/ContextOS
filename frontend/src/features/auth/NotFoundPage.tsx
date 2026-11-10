import { Link } from "react-router-dom";
import { EmptyState, Button } from "@/components/ui";

export function NotFoundPage() {
  return (
    <EmptyState
      title="Page not found"
      description="This page doesn’t exist, or the record it pointed to belongs to another organisation."
      action={
        <Link to="/">
          <Button variant="outline" size="sm">
            Back to overview
          </Button>
        </Link>
      }
    />
  );
}
