"use client";

import { CircleAlert } from "lucide-react";
import { useActionState } from "react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Spinner } from "@/components/ui/spinner";

import { loginAction, type LoginState } from "./actions";

const initialState: LoginState = { error: null };

export function LoginForm({ next }: { next: string }) {
  const [state, formAction, pending] = useActionState(loginAction, initialState);
  return (
    <form action={formAction} className="flex flex-col gap-5" noValidate>
      <input type="hidden" name="next" value={next} />
      <div className="grid gap-2">
        <Label htmlFor="username" className="text-sm font-medium text-fg-2">
          Username
        </Label>
        <Input
          id="username"
          name="username"
          type="text"
          autoComplete="username"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          required
          maxLength={128}
          autoFocus
          aria-invalid={state.error ? true : undefined}
          aria-describedby={state.error ? "login-error" : undefined}
          className="h-10 bg-white/[0.03] px-3 text-base md:text-base"
        />
      </div>
      <div className="grid gap-2">
        <Label htmlFor="password" className="text-sm font-medium text-fg-2">
          Password
        </Label>
        <Input
          id="password"
          name="password"
          type="password"
          autoComplete="current-password"
          required
          maxLength={512}
          aria-invalid={state.error ? true : undefined}
          aria-describedby={state.error ? "login-error" : undefined}
          className="h-10 bg-white/[0.03] px-3 text-base md:text-base"
        />
      </div>
      <div aria-live="polite" className="-my-2">
        {state.error ? (
          <p id="login-error" role="alert" className="flex items-start gap-2 text-sm text-foreground">
            <CircleAlert className="mt-0.5 size-4 flex-none text-health-bad" aria-hidden="true" />
            {state.error}
          </p>
        ) : null}
      </div>
      <Button type="submit" disabled={pending} className="h-10 w-full text-sm">
        {pending ? <Spinner className="size-4" /> : null}
        {pending ? "Signing in" : "Sign in"}
      </Button>
    </form>
  );
}
