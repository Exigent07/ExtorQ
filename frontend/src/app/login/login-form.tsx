"use client";

import { CircleAlert } from "lucide-react";
import { useActionState } from "react";

import { Spinner } from "@/components/ui/spinner";

import { loginAction, type LoginState } from "./actions";

const initialState: LoginState = { error: null };

export function LoginForm({ next }: { next: string }) {
  const [state, formAction, pending] = useActionState(loginAction, initialState);
  return (
    <form action={formAction} className="flex flex-col gap-4" noValidate>
      <input type="hidden" name="next" value={next} />
      <div className="flex flex-col gap-2">
        <label htmlFor="username" className="text-sm font-medium text-ink">
          Username
        </label>
        <input
          id="username"
          name="username"
          type="text"
          autoComplete="username"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          required
          maxLength={128}
          aria-invalid={state.error ? true : undefined}
          aria-describedby={state.error ? "login-error" : undefined}
          className="h-10 rounded-md border border-control bg-ground px-3 text-base text-ink outline-none placeholder:text-muted-foreground focus-visible:border-ring"
        />
      </div>
      <div className="flex flex-col gap-2">
        <label htmlFor="password" className="text-sm font-medium text-ink">
          Password
        </label>
        <input
          id="password"
          name="password"
          type="password"
          autoComplete="current-password"
          required
          maxLength={512}
          aria-invalid={state.error ? true : undefined}
          aria-describedby={state.error ? "login-error" : undefined}
          className="h-10 rounded-md border border-control bg-ground px-3 text-base text-ink outline-none focus-visible:border-ring"
        />
      </div>
      <div aria-live="polite" className="min-h-5">
        {state.error ? (
          <p id="login-error" role="alert" className="flex items-start gap-2 text-sm text-ink">
            <CircleAlert className="mt-0.5 size-4 flex-none text-bad" aria-hidden="true" />
            {state.error}
          </p>
        ) : null}
      </div>
      <button
        type="submit"
        disabled={pending}
        className="inline-flex h-10 items-center justify-center gap-2 rounded-full bg-primary px-5 text-sm font-medium text-primary-foreground transition-opacity hover:opacity-90 disabled:opacity-60"
      >
        {pending ? <Spinner className="size-4" /> : null}
        {pending ? "Signing in" : "Sign in"}
      </button>
    </form>
  );
}
