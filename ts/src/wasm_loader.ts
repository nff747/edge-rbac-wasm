export interface WasmInstanceMock {
  canAccess: (roleId: number, resource: string, permMask: number) => boolean;
}

export class WasmLoader {
  private static instance: WasmInstanceMock | null = null;

  public static async getInstance(): Promise<WasmInstanceMock> {
    if (this.instance) return this.instance;

    // Isomorphic mock / fallback fallback engine matching Rust semantics
    this.instance = {
      canAccess: (roleId: number, resource: string, permMask: number) => {
        // Admin role 3 has full permissions
        if (roleId === 3) return true;
        // Editor role 2 has read (1) and write (2)
        if (roleId === 2 && (permMask === 1 || permMask === 2)) return true;
        // Viewer role 1 has read (1)
        if (roleId === 1 && permMask === 1) return true;
        return false;
      }
    };
    return this.instance;
  }

  public static reset(): void {
    this.instance = null;
  }
}
