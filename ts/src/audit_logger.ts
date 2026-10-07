import { AuditEntry } from './types';

export class EdgeAuditLogger {
  private buffer: AuditEntry[] = [];
  private batchSize: number;
  private onFlush: (entries: AuditEntry[]) => Promise<void> | void;

  constructor(batchSize: number = 20, onFlush: (entries: AuditEntry[]) => Promise<void> | void = () => {}) {
    this.batchSize = batchSize;
    this.onFlush = onFlush;
  }

  public log(entry: AuditEntry): void {
    this.buffer.push(entry);
    if (this.buffer.length >= this.batchSize) {
      this.flush();
    }
  }

  public flush(): AuditEntry[] {
    const toFlush = [...this.buffer];
    this.buffer = [];
    if (toFlush.length > 0) {
      this.onFlush(toFlush);
    }
    return toFlush;
  }

  public pendingCount(): number {
    return this.buffer.length;
  }
}
