"use client";

import { Check, Lock } from "lucide-react";
import { useActionState, useId, useState } from "react";

import { type StateActionResult, updateAlertStateAction } from "@/app/(console)/actions";
import { Timestamp } from "@/components/console/time";
import { UntrustedText } from "@/components/console/untrusted-text";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Spinner } from "@/components/ui/spinner";
import { Textarea } from "@/components/ui/textarea";
import { ANALYST_STATUSES, type AnalystStateView } from "@/lib/api/schemas";

import { StatusMark } from "./marks";

const initial: StateActionResult = { ok: false, message: null, savedAt: null };

function Outcome({ result, pending }: { result: StateActionResult; pending: boolean }) {
  if (pending) return <span className="text-muted-foreground">Saving…</span>;
  if (result.ok && result.savedAt) {
    return (
      <span className="inline-flex items-center gap-1 text-health-ok">
        <Check className="size-3.5" aria-hidden="true" /> Saved
      </span>
    );
  }
  return result.message ? <span className="text-health-bad">{result.message}</span> : null;
}

/**
 * The Analyst status card body: current state, and for analysts the status + note form (a
 * real form: it also works as a no-JavaScript post, and the smoke test replays it as the
 * viewer to prove the server action refuses). Viewers see the state read-only.
 */
export function StatusForm({ alertId, state, canEdit }: { alertId: string; state: AnalystStateView; canEdit: boolean }) {
  const [result, formAction, pending] = useActionState(updateAlertStateAction.bind(null, alertId), initial);
  const [status, setStatus] = useState<string>(state.status);
  const [note, setNote] = useState("");
  const statusId = useId();
  const noteId = useId();
  // Saving records an audited action: only offered once the status or the note changed.
  const dirty = status !== state.status || note.trim() !== "";
  // A saved note is in the audit log now: clear the field for the next one.
  const [seenSave, setSeenSave] = useState(result.savedAt);
  if (result.savedAt !== seenSave) {
    setSeenSave(result.savedAt);
    if (result.ok) setNote("");
  }

  return (
    <div className="grid gap-4">
      <dl className="grid gap-2.5 text-sm">
        <div className="flex items-center justify-between gap-4">
          <dt className="text-muted-foreground">Current</dt>
          <dd>
            <StatusMark status={state.status} className="text-foreground" />
          </dd>
        </div>
        <div className="flex items-start justify-between gap-4">
          <dt className="flex-none text-muted-foreground">Updated</dt>
          <dd className="min-w-0 text-right">
            {state.recorded ? (
              <>
                <Timestamp value={state.updated_at} />
                {state.updated_by ? (
                  <span className="block text-xs text-muted-foreground">
                    by <UntrustedText value={state.updated_by} limit={40} />
                  </span>
                ) : null}
              </>
            ) : (
              <span className="text-xs text-muted-foreground">No analyst has acted yet</span>
            )}
          </dd>
        </div>
        {state.assignee ? (
          <div className="flex items-start justify-between gap-4">
            <dt className="flex-none text-muted-foreground">Assignee</dt>
            <dd className="min-w-0 text-right text-fg-2">
              <UntrustedText value={state.assignee} limit={40} />
            </dd>
          </div>
        ) : null}
        {state.note ? (
          <div className="grid gap-1">
            <dt className="text-muted-foreground">Note</dt>
            <dd className="rounded-lg bg-white/[0.02] px-3 py-2 text-sm leading-relaxed text-fg-2 ring-1 ring-hairline ring-inset">
              <UntrustedText value={state.note} limit={280} multiline />
            </dd>
          </div>
        ) : null}
      </dl>

      {canEdit ? (
        <form action={formAction} className="grid gap-3 border-t border-hairline-soft pt-4">
          <input type="hidden" name="expected_updated_at" value={state.updated_at ?? ""} />
          <input type="hidden" name="status" value={status} />
          <div className="grid gap-1.5">
            <Label htmlFor={statusId} className="text-xs font-normal text-muted-foreground">
              Set status
            </Label>
            <Select value={status} onValueChange={setStatus}>
              <SelectTrigger id={statusId} className="w-full">
                <SelectValue>
                  <StatusMark status={status} className="text-foreground" />
                </SelectValue>
              </SelectTrigger>
              <SelectContent position="popper" align="start">
                {ANALYST_STATUSES.map((value) => (
                  <SelectItem key={value} value={value}>
                    <StatusMark status={value} className="text-foreground" />
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="grid gap-1.5">
            <Label htmlFor={noteId} className="text-xs font-normal text-muted-foreground">
              Note (optional, recorded in the audit log)
            </Label>
            <Textarea
              id={noteId}
              name="note"
              rows={3}
              maxLength={2048}
              placeholder="What did you check?"
              className="min-h-20 text-sm"
              value={note}
              onChange={(event) => setNote(event.target.value)}
            />
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <Button type="submit" disabled={pending || !dirty} className="h-8 px-3">
              {pending ? <Spinner className="size-3.5" /> : null}
              {pending ? "Saving" : "Save status"}
            </Button>
            <span aria-live="polite" className="text-xs">
              <Outcome result={result} pending={false} />
            </span>
          </div>
        </form>
      ) : (
        <p className="flex items-start gap-2 rounded-lg bg-white/[0.02] px-3 py-2.5 text-xs leading-relaxed text-muted-foreground ring-1 ring-hairline ring-inset">
          <Lock className="mt-0.5 size-3.5 flex-none" aria-hidden="true" />
          Viewer accounts can read investigations but cannot change their status. The API enforces this as well.
        </p>
      )}
    </div>
  );
}
