/** Client HTTP minimale dell'API v1. Funziona in browser, estensione, Node e React Native. */

export class ApiError extends Error {
  constructor(public status: number, public code: string, message?: string) {
    super(message ?? code);
    this.name = "ApiError";
  }
}

export interface ApiOptions {
  baseUrl: string;
  token?: string;
  fetch?: typeof fetch;
}

export class Api {
  baseUrl: string;
  token?: string;
  private f: typeof fetch;

  constructor(opts: ApiOptions) {
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.token = opts.token;
    this.f = opts.fetch ?? globalThis.fetch.bind(globalThis);
  }

  private headers(extra: Record<string, string> = {}): Record<string, string> {
    return this.token ? { ...extra, Authorization: `Bearer ${this.token}` } : extra;
  }

  private async handle<T>(res: Response): Promise<T> {
    if (res.ok) {
      const type = res.headers.get("content-type") ?? "";
      return (type.includes("application/json") ? await res.json() : new Uint8Array(await res.arrayBuffer())) as T;
    }
    let code = "http_error";
    let message = `HTTP ${res.status}`;
    try {
      const j = (await res.json()) as { error?: string; message?: string };
      code = j.error ?? code;
      message = j.message ?? code;
    } catch {
      /* risposta non JSON */
    }
    throw new ApiError(res.status, code, message);
  }

  async req<T>(method: string, path: string, body?: unknown): Promise<T> {
    const res = await this.f(`${this.baseUrl}/api/v1${path}`, {
      method,
      headers: this.headers(body === undefined ? {} : { "Content-Type": "application/json" }),
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "omit",
      cache: "no-store",
    });
    return this.handle<T>(res);
  }

  get<T>(path: string) { return this.req<T>("GET", path); }
  post<T>(path: string, body: unknown = {}) { return this.req<T>("POST", path, body); }
  put<T>(path: string, body: unknown) { return this.req<T>("PUT", path, body); }
  patch<T>(path: string, body: unknown) { return this.req<T>("PATCH", path, body); }
  del<T>(path: string) { return this.req<T>("DELETE", path); }

  async putBinary(path: string, data: Uint8Array): Promise<void> {
    const res = await this.f(`${this.baseUrl}/api/v1${path}`, {
      method: "PUT",
      headers: this.headers({ "Content-Type": "application/octet-stream" }),
      body: data,
      credentials: "omit",
    });
    await this.handle(res);
  }

  async getBinary(path: string): Promise<Uint8Array> {
    const res = await this.f(`${this.baseUrl}/api/v1${path}`, { headers: this.headers(), credentials: "omit", cache: "no-store" });
    return this.handle<Uint8Array>(res);
  }
}
