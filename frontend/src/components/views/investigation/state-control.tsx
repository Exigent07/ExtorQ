"use client";

import { Check, Lock } from "lucide-react";
import { useActionState, useId } from "react";

import { type StateActionResult, updateAlertStateAction } from "@/app/(console)/actions";
import { Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { Spinner } from "@/components/ui/spinner";
import { ANALYST_STATUSES, type AnalystStateView } from "@/lib/api/schemas";
import { analystStatusLabel } from "@/lib/format";

const initial: StateActionResult = { ok: false, message: null, savedAt: null };

/**
 * Analyst workflow state. The server action re-checks the session and the analyst role, and
 * the API enforces the role again; viewers see the state read-only. `expected_updated_at`
 * turns a concurrent change into a conflict instead of a silent overwrite.
 */
export function AnalystStateControl({
  alertId,
  state,
  canEdit,
}: {
  alertId: string;
  state: AnalystStateView;
  canEdit: boolean;
}) {
  const [result, formAction, pending] = useActionState(updateAlertStateAction.bind(null, alertId), initial);
  const noteId = useId();
  const statusId = useId();

  return (
    <div>
      <dl className="mb-3 grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-xs">
        <dt className="text-muted-foreground">Current</dt>
        <dd className="text-right text-sm text-ink">{analystStatusLabel(state.status)}</dd>
        <dt className="text-muted-foreground">Updated</dt>
        <dd className="text-right">
          {state.recorded ? (
            <>
              <Timestamp value={state.updated_at} />
              {state.updated_by ? (
                <span className="text-muted-foreground">
                  {" by "}
                  <UntrustedText value={state.updated_by} limit={40} />
                </span>
              ) : null}
            </>
          ) : (
            <span className="text-muted-foreground">No analyst has acted yet</span>
          )}
        </dd>
        {state.note ? (
          <>
            <dt className="text-muted-foreground">Note</dt>
            <dd className="text-right text-ink-2">
              <UntrustedText value={state.note} limit={240} />
            </dd>
          </>
        ) : null}
      </dl>

      {canEdit ? (
        <form action={formAction} className="flex flex-col gap-3">
          <input type="hidden" name="expected_updated_at" value={state.updated_at ?? ""} />
          <div className="flex flex-col gap-1">
            <label htmlFor={statusId} className="text-xs text-muted-foreground">
              Set status
            </label>
            <select
              id={statusId}
              name="status"
              defaultValue={state.status}
              className="h-8 rounded-md border border-control bg-ground px-2 text-sm text-ink outline-none focus-visible:border-ring"
            >
              {ANALYST_STATUSES.map((s) => (
                <option key={s} value={s}>
                  {analystStatusLabel(s)}
                </option>
              ))}
            </select>
          </div>
          <div className="flex flex-col gap-1">
            <label htmlFor={noteId} className="text-xs text-muted-foreground">
              Note (optional, recorded in the audit log)
            </label>
            <textarea
              id={noteId}
              name="note"
              rows={3}
              maxLength={2048}
              className="rounded-md border border-control bg-ground px-2 py-1.5 text-sm text-ink outline-none focus-visible:border-ring"
            />
          </div>
          <div className="flex items-center gap-3">
            <button
              type="submit"
              disabled={pending}
              className="inline-flex h-8 items-center gap-2 rounded-full bg-primary px-4 text-sm font-medium text-primary-foreground transition-opacity hover:opacity-90 disabled:opacity-60"
            >
              {pending ? <Spinner className="size-3.5" /> : null}
              {pending ? "Saving" : "Save status"}
            </button>
            <span aria-live="polite" className="text-xs">
              {result.ok && result.savedAt ? (
                <span className="inline-flex items-center gap-1 text-ok">
                  <Check className="size-3.5" aria-hidden="true" /> Saved
                </span>
              ) : result.message ? (
                <span className="text-bad">{result.message}</span>
              ) : null}
            </span>
          </div>
        </form>
      ) : (
        <p className="flex items-start gap-2 rounded-md border border-border px-3 py-2 text-xs text-muted-foreground">
          <Lock className="mt-0.5 size-3.5 flex-none" aria-hidden="true" />
          Viewer accounts can read investigations but cannot change their status. The API enforces this as well.
        </p>
      )}
    </div>
  );
}
