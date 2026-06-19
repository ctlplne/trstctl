import { useNavigate } from "react-router-dom";
import { Button } from "@/components/ui/button";
import { beginLogin, useAuth } from "@/auth/AuthProvider";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export function Login() {
  const { previewAvailable, startPreview } = useAuth();
  const navigate = useNavigate();

  function enterPreview() {
    startPreview();
    navigate("/coverage");
  }

  return (
    <main className="flex min-h-screen items-center justify-center p-6">
      <Card className="w-full max-w-sm">
        <CardHeader>
          <CardTitle>Sign in to trstctl</CardTitle>
        </CardHeader>
        <CardContent>
          <p className="mb-4 text-sm text-muted-foreground">
            Authenticate with your organization's identity provider to manage credentials.
          </p>
          <Button className="w-full" onClick={beginLogin}>
            Sign in with SSO
          </Button>
          {previewAvailable && (
            <div className="mt-4 border-t border-border pt-4">
              <p className="mb-3 text-xs text-muted-foreground">
                Local dev preview uses an in-memory tenant and stores no token. Production builds still require SSO.
              </p>
              <Button className="w-full" variant="outline" onClick={enterPreview}>
                Preview UI without backend
              </Button>
            </div>
          )}
        </CardContent>
      </Card>
    </main>
  );
}
