import { beforeEach, describe, expect, it, vi } from "vitest";
import { NextRequest } from "next/server";
import { GET } from "./route";

vi.mock("@/lib/supabase/server", () => ({
  createSupabaseServerClient: vi.fn(),
}));

vi.mock("@/lib/observability", () => ({
  reportError: vi.fn(),
}));

import { createSupabaseServerClient } from "@/lib/supabase/server";

const mockCreateSupabaseServerClient = vi.mocked(createSupabaseServerClient);

describe("GET /auth/callback", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  function mockSupabase({
    exchangeError = null,
    user = null,
  }: {
    exchangeError?: { message: string; status?: number; code?: string } | null;
    user?: { id: string } | null;
  }) {
    mockCreateSupabaseServerClient.mockResolvedValue({
      auth: {
        exchangeCodeForSession: vi.fn().mockResolvedValue({ error: exchangeError }),
        getUser: vi.fn().mockResolvedValue({ data: { user } }),
      },
    } as never);
  }

  it("redirects with missing_code when code is absent", async () => {
    const req = new NextRequest("https://example.com/auth/callback");
    const res = await GET(req);

    expect(res.status).toBe(307);
    expect(res.headers.get("location")).toBe("https://example.com/?error=missing_code");
  });

  it("redirects to next path on successful exchange", async () => {
    mockSupabase({ exchangeError: null, user: { id: "u1" } });

    const req = new NextRequest("https://example.com/auth/callback?code=abc&next=%2Fdashboard");
    const res = await GET(req);

    expect(res.status).toBe(307);
    expect(res.headers.get("location")).toBe("https://example.com/dashboard");
  });

  it("sanitizes unsafe next path to root", async () => {
    mockSupabase({ exchangeError: null, user: { id: "u1" } });

    const req = new NextRequest(
      "https://example.com/auth/callback?code=abc&next=https%3A%2F%2Fevil.example"
    );
    const res = await GET(req);

    expect(res.status).toBe(307);
    expect(res.headers.get("location")).toBe("https://example.com/");
  });

  it("returns auth_failed when exchange fails and user is not authenticated", async () => {
    mockSupabase({
      exchangeError: { message: "invalid grant", status: 400, code: "invalid_grant" },
      user: null,
    });

    const req = new NextRequest("https://example.com/auth/callback?code=bad");
    const res = await GET(req);

    expect(res.status).toBe(307);
    expect(res.headers.get("location")).toBe("https://example.com/?error=auth_failed");
  });

  it("redirects to next when exchange fails but user already exists", async () => {
    mockSupabase({
      exchangeError: { message: "already used", status: 400, code: "invalid_grant" },
      user: { id: "u1" },
    });

    const req = new NextRequest("https://example.com/auth/callback?code=used&next=%2Fsettings");
    const res = await GET(req);

    expect(res.status).toBe(307);
    expect(res.headers.get("location")).toBe("https://example.com/settings");
  });
});
