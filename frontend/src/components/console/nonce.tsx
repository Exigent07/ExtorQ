"use client";

import { setNonce } from "get-nonce";
import { createContext, type ReactNode, useContext } from "react";

/**
 * The per-request CSP nonce (set by src/proxy.ts, read by the root layout) for the library
 * code that injects <style> elements: Radix ScrollArea (via `useNonce`) and the scroll lock
 * of every Radix modal (react-remove-scroll -> react-style-singleton, which reads it from
 * `get-nonce`). The production policy allows <style> elements only with this nonce.
 */
const NonceContext = createContext<string | undefined>(undefined);

export function NonceProvider({ nonce, children }: { nonce: string | undefined; children: ReactNode }) {
  // Idempotent global configuration, set before any dialog, popover or menu can open.
  if (typeof window !== "undefined" && nonce) setNonce(nonce);
  return <NonceContext.Provider value={nonce}>{children}</NonceContext.Provider>;
}

export function useNonce(): string | undefined {
  return useContext(NonceContext);
}
