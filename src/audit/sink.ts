import type { AuditEvent } from "./index.js";

export interface AuditSink {
  /** A mutating operation is denied unless the sink reports ready. */
  ready(): Promise<boolean> | boolean;
  append(event: Readonly<AuditEvent>): Promise<void>;
}

export class MemoryAuditSink implements AuditSink {
  readonly #events: Readonly<AuditEvent>[] = [];
  constructor(private available = true) {}
  ready(): boolean { return this.available; }
  setReady(ready: boolean): void { this.available = ready; }
  async append(event: Readonly<AuditEvent>): Promise<void> { if (!this.available) throw new Error("AUDIT_SINK_UNAVAILABLE"); this.#events.push(event); }
  events(): readonly Readonly<AuditEvent>[] { return Object.freeze([...this.#events]); }
}
