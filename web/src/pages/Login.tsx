import { Button } from "@/components/ui/button";
import { beginLogin } from "@/auth/AuthProvider";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export function Login() {
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
        </CardContent>
      </Card>
    </main>
  );
}
