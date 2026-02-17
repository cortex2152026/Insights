import { describe, it, expect, vi, beforeEach } from "vitest";
import {
  listWebhooks,
  createWebhook,
  updateWebhook,
  deleteWebhook,
  testWebhook,
} from "./webhooks";

// Mock the createSupabaseServerClient function
vi.mock("@/lib/supabase/server", () => ({
  createSupabaseServerClient: vi.fn(),
}));

// Import the mocked function to control its behavior
import { createSupabaseServerClient } from "@/lib/supabase/server";
const mockCreateSupabaseServerClient = vi.mocked(createSupabaseServerClient);

// Helper to create a mock Supabase client
function createMockSupabase(options: {
  user?: { id: string } | null;
  authError?: Error | null;
}) {
  return {
    auth: {
      getUser: vi.fn().mockResolvedValue({
        data: { user: options.user ?? null },
        error: options.authError ?? null,
      }),
    },
    from: vi.fn(),
  };
}

// Valid UUID for testing
const mockUserId = "a1b2c3d4-e5f6-7890-abcd-ef1234567890";
const mockWebhookId = "b2c3d4e5-f6a7-8901-bcde-f23456789012";

describe("listWebhooks", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns error when not authenticated", async () => {
    const mockSupabase = createMockSupabase({ user: null });
    mockCreateSupabaseServerClient.mockResolvedValue(mockSupabase as never);

    const result = await listWebhooks();

    expect(result).toEqual({
      success: false,
      error: "Not authenticated",
    });
  });

  it("returns error when auth returns error", async () => {
    const mockSupabase = createMockSupabase({
      user: null,
      authError: new Error("Auth failed"),
    });
    mockCreateSupabaseServerClient.mockResolvedValue(mockSupabase as never);

    const result = await listWebhooks();

    expect(result).toEqual({
      success: false,
      error: "Not authenticated",
    });
  });

  it("successfully returns empty array when no webhooks", async () => {
    const mockSupabase = createMockSupabase({ user: { id: mockUserId } });
    const mockOrder = vi.fn().mockResolvedValue({ data: [], error: null });
    const mockEq = vi.fn().mockReturnValue({ order: mockOrder });
    const mockSelect = vi.fn().mockReturnValue({ eq: mockEq });
    mockSupabase.from.mockReturnValue({ select: mockSelect });
    mockCreateSupabaseServerClient.mockResolvedValue(mockSupabase as never);

    const result = await listWebhooks();

    expect(result).toEqual({
      success: true,
      data: [],
    });
    expect(mockSupabase.from).toHaveBeenCalledWith("webhook_endpoints");
  });

  it("successfully returns user webhooks with masked secrets", async () => {
    const mockSupabase = createMockSupabase({ user: { id: mockUserId } });
    const mockWebhooks = [
      {
        id: mockWebhookId,
        url: "https://example.com/webhook",
        secret: "whsec_1234567890abcdef1234567890abcdef",
        events: ["release.published"],
        enabled: true,
        created_at: "2026-01-11T00:00:00Z",
        updated_at: "2026-01-11T00:00:00Z",
        last_triggered_at: null,
      },
    ];
    const mockOrder = vi.fn().mockResolvedValue({ data: mockWebhooks, error: null });
    const mockEq = vi.fn().mockReturnValue({ order: mockOrder });
    const mockSelect = vi.fn().mockReturnValue({ eq: mockEq });
    mockSupabase.from.mockReturnValue({ select: mockSelect });
    mockCreateSupabaseServerClient.mockResolvedValue(mockSupabase as never);

    const result = await listWebhooks();

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data).toHaveLength(1);
      expect(result.data[0].url).toBe("https://example.com/webhook");
      expect(result.data[0].secret_preview).toBe("whsec_1234****");
      expect(result.data[0].events).toEqual(["release.published"]);
    }
  });

  it("returns error on database failure", async () => {
    const mockSupabase = createMockSupabase({ user: { id: mockUserId } });
    const mockOrder = vi
      .fn()
      .mockResolvedValue({ data: null, error: { message: "DB error" } });
    const mockEq = vi.fn().mockReturnValue({ order: mockOrder });
    const mockSelect = vi.fn().mockReturnValue({ eq: mockEq });
    mockSupabase.from.mockReturnValue({ select: mockSelect });
    mockCreateSupabaseServerClient.mockResolvedValue(mockSupabase as never);

    const result = await listWebhooks();

    expect(result).toEqual({
      success: false,
      error: "Failed to fetch webhooks",
    });
  });
});

describe("createWebhook", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns error for invalid URL", async () => {
    const result = await createWebhook({ url: "not-a-url" });

    expect(result).toEqual({
      success: false,
      error: "Invalid URL format",
    });
  });

  it("returns error for non-HTTPS URL", async () => {
    const result = await createWebhook({ url: "http://example.com/webhook" });

    expect(result).toEqual({
      success: false,
      error: "Webhook URL must use HTTPS",
    });
  });

  it("returns error for URL exceeding max length", async () => {
    const longUrl = "https://example.com/" + "a".repeat(2050);
    const result = await createWebhook({ url: longUrl });

    expect(result).toEqual({
      success: false,
      error: "URL must be 2048 characters or less",
    });
  });

  it("returns error for empty events array", async () => {
    const result = await createWebhook({
      url: "https://example.com/webhook",
      events: [],
    });

    expect(result).toEqual({
      success: false,
      error: "At least one event type is required",
    });
  });

  it("returns error for invalid event type", async () => {
    const result = await createWebhook({
      url: "https://example.com/webhook",
      // @ts-expect-error - Testing invalid event type
      events: ["invalid.event"],
    });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toContain("Invalid");
    }
  });

  it("returns error when not authenticated", async () => {
    const mockSupabase = createMockSupabase({ user: null });
    mockCreateSupabaseServerClient.mockResolvedValue(mockSupabase as never);

    const result = await createWebhook({ url: "https://example.com/webhook" });

    expect(result).toEqual({
      success: false,
      error: "Not authenticated",
    });
  });

  it("successfully creates webhook with default events", async () => {
    const mockSupabase = createMockSupabase({ user: { id: mockUserId } });
    const mockCreatedWebhook = {
      id: mockWebhookId,
      url: "https://example.com/webhook",
      events: ["release.published"],
      enabled: true,
      created_at: "2026-01-11T00:00:00Z",
    };
    const mockSingle = vi
      .fn()
      .mockResolvedValue({ data: mockCreatedWebhook, error: null });
    const mockSelectReturn = vi.fn().mockReturnValue({ single: mockSingle });
    const mockInsert = vi.fn().mockReturnValue({ select: mockSelectReturn });
    mockSupabase.from.mockReturnValue({ insert: mockInsert });
    mockCreateSupabaseServerClient.mockResolvedValue(mockSupabase as never);

    const result = await createWebhook({ url: "https://example.com/webhook" });

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.id).toBe(mockWebhookId);
      expect(result.data.url).toBe("https://example.com/webhook");
      // Secret should start with whsec_ prefix
      expect(result.data.secret).toMatch(/^whsec_[a-f0-9]{32}$/);
      expect(result.data.events).toEqual(["release.published"]);
    }
    expect(mockInsert).toHaveBeenCalledWith(
      expect.objectContaining({
        user_id: mockUserId,
        url: "https://example.com/webhook",
        secret: expect.stringMatching(/^whsec_[a-f0-9]{32}$/),
        events: ["release.published"],
      })
    );
  });

  it("successfully creates webhook with custom events", async () => {
    const mockSupabase = createMockSupabase({ user: { id: mockUserId } });
    const mockCreatedWebhook = {
      id: mockWebhookId,
      url: "https://example.com/webhook",
      events: ["release.published", "release.revised"],
      enabled: true,
      created_at: "2026-01-11T00:00:00Z",
    };
    const mockSingle = vi
      .fn()
      .mockResolvedValue({ data: mockCreatedWebhook, error: null });
    const mockSelectReturn = vi.fn().mockReturnValue({ single: mockSingle });
    const mockInsert = vi.fn().mockReturnValue({ select: mockSelectReturn });
    mockSupabase.from.mockReturnValue({ insert: mockInsert });
    mockCreateSupabaseServerClient.mockResolvedValue(mockSupabase as never);

    const result = await createWebhook({
      url: "https://example.com/webhook",
      events: ["release.published", "release.revised"],
    });

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.events).toEqual(["release.published", "release.revised"]);
    }
    expect(mockInsert).toHaveBeenCalledWith(
      expect.objectContaining({
        events: ["release.published", "release.revised"],
      })
    );
  });

  it("returns error on database failure", async () => {
    const mockSupabase = createMockSupabase({ user: { id: mockUserId } });
    const mockSingle = vi
      .fn()
      .mockResolvedValue({ data: null, error: { code: "50000", message: "DB error" } });
    const mockSelectReturn = vi.fn().mockReturnValue({ single: mockSingle });
    const mockInsert = vi.fn().mockReturnValue({ select: mockSelectReturn });
    mockSupabase.from.mockReturnValue({ insert: mockInsert });
    mockCreateSupabaseServerClient.mockResolvedValue(mockSupabase as never);

    const result = await createWebhook({ url: "https://example.com/webhook" });

    expect(result).toEqual({
      success: false,
      error: "Failed to create webhook",
    });
  });
});

describe("updateWebhook", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns error for invalid webhook ID format", async () => {
    const result = await updateWebhook("invalid-id", { enabled: false });

    expect(result).toEqual({
      success: false,
      error: "Invalid webhook ID",
    });
  });

  it("returns error for no fields to update", async () => {
    const result = await updateWebhook(mockWebhookId, {});

    expect(result).toEqual({
      success: false,
      error: "No fields to update",
    });
  });

  it("returns error for invalid URL in update", async () => {
    const result = await updateWebhook(mockWebhookId, {
      url: "http://example.com/webhook",
    });

    expect(result).toEqual({
      success: false,
      error: "Webhook URL must use HTTPS",
    });
  });

  it("returns error when not authenticated", async () => {
    const mockSupabase = createMockSupabase({ user: null });
    mockCreateSupabaseServerClient.mockResolvedValue(mockSupabase as never);

    const result = await updateWebhook(mockWebhookId, { enabled: false });

    expect(result).toEqual({
      success: false,
      error: "Not authenticated",
    });
  });

  it("returns error when webhook not found", async () => {
    const mockSupabase = createMockSupabase({ user: { id: mockUserId } });
    const mockSingle = vi
      .fn()
      .mockResolvedValue({ data: null, error: { code: "PGRST116", message: "No rows" } });
    const mockEqUser = vi.fn().mockReturnValue({ single: mockSingle });
    const mockEqId = vi.fn().mockReturnValue({ eq: mockEqUser });
    const mockSelect = vi.fn().mockReturnValue({ eq: mockEqId });
    mockSupabase.from.mockReturnValue({ select: mockSelect });
    mockCreateSupabaseServerClient.mockResolvedValue(mockSupabase as never);

    const result = await updateWebhook(mockWebhookId, { enabled: false });

    expect(result).toEqual({
      success: false,
      error: "Webhook not found",
    });
  });

  it("successfully updates webhook enabled status", async () => {
    const mockSupabase = createMockSupabase({ user: { id: mockUserId } });

    // First call: select to check webhook exists
    const mockSingleSelect = vi.fn().mockResolvedValue({
      data: { id: mockWebhookId },
      error: null,
    });
    const mockEqUser = vi.fn().mockReturnValue({ single: mockSingleSelect });
    const mockEqId = vi.fn().mockReturnValue({ eq: mockEqUser });
    const mockSelect = vi.fn().mockReturnValue({ eq: mockEqId });

    // Second call: update
    const updatedWebhook = {
      id: mockWebhookId,
      url: "https://example.com/webhook",
      secret: "whsec_1234567890abcdef1234567890abcdef",
      events: ["release.published"],
      enabled: false,
      created_at: "2026-01-11T00:00:00Z",
      updated_at: "2026-01-11T01:00:00Z",
      last_triggered_at: null,
    };
    const mockSingleUpdate = vi.fn().mockResolvedValue({
      data: updatedWebhook,
      error: null,
    });
    const mockSelectUpdate = vi.fn().mockReturnValue({ single: mockSingleUpdate });
    const mockEqUpdate = vi.fn().mockReturnValue({ select: mockSelectUpdate });
    const mockUpdate = vi.fn().mockReturnValue({ eq: mockEqUpdate });

    mockSupabase.from.mockReturnValueOnce({ select: mockSelect });
    mockSupabase.from.mockReturnValueOnce({ update: mockUpdate });
    mockCreateSupabaseServerClient.mockResolvedValue(mockSupabase as never);

    const result = await updateWebhook(mockWebhookId, { enabled: false });

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.enabled).toBe(false);
      expect(result.data.secret_preview).toBe("whsec_1234****");
    }
  });
});

describe("deleteWebhook", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it("returns error for invalid webhook ID format", async () => {
    const result = await deleteWebhook("not-a-uuid");

    expect(result).toEqual({
      success: false,
      error: "Invalid webhook ID",
    });
  });

  it("returns error when not authenticated", async () => {
    const mockSupabase = createMockSupabase({ user: null });
    mockCreateSupabaseServerClient.mockResolvedValue(mockSupabase as never);

    const result = await deleteWebhook(mockWebhookId);

    expect(result).toEqual({
      success: false,
      error: "Not authenticated",
    });
  });

  it("successfully deletes webhook", async () => {
    const mockSupabase = createMockSupabase({ user: { id: mockUserId } });
    const mockEqUser = vi.fn().mockResolvedValue({ error: null });
    const mockEqId = vi.fn().mockReturnValue({ eq: mockEqUser });
    const mockDelete = vi.fn().mockReturnValue({ eq: mockEqId });
    mockSupabase.from.mockReturnValue({ delete: mockDelete });
    mockCreateSupabaseServerClient.mockResolvedValue(mockSupabase as never);

    const result = await deleteWebhook(mockWebhookId);

    expect(result).toEqual({
      success: true,
      data: undefined,
    });
    expect(mockSupabase.from).toHaveBeenCalledWith("webhook_endpoints");
    expect(mockDelete).toHaveBeenCalled();
  });

  it("returns error on database failure", async () => {
    const mockSupabase = createMockSupabase({ user: { id: mockUserId } });
    const mockEqUser = vi.fn().mockResolvedValue({ error: { message: "DB error" } });
    const mockEqId = vi.fn().mockReturnValue({ eq: mockEqUser });
    const mockDelete = vi.fn().mockReturnValue({ eq: mockEqId });
    mockSupabase.from.mockReturnValue({ delete: mockDelete });
    mockCreateSupabaseServerClient.mockResolvedValue(mockSupabase as never);

    const result = await deleteWebhook(mockWebhookId);

    expect(result).toEqual({
      success: false,
      error: "Failed to delete webhook",
    });
  });
});

describe("testWebhook", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Mock global fetch
    global.fetch = vi.fn();
  });

  it("returns error for invalid webhook ID format", async () => {
    const result = await testWebhook("invalid-id");

    expect(result).toEqual({
      success: false,
      error: "Invalid webhook ID",
    });
  });

  it("returns error when not authenticated", async () => {
    const mockSupabase = createMockSupabase({ user: null });
    mockCreateSupabaseServerClient.mockResolvedValue(mockSupabase as never);

    const result = await testWebhook(mockWebhookId);

    expect(result).toEqual({
      success: false,
      error: "Not authenticated",
    });
  });

  it("returns error when webhook not found", async () => {
    const mockSupabase = createMockSupabase({ user: { id: mockUserId } });
    const mockSingle = vi
      .fn()
      .mockResolvedValue({ data: null, error: { code: "PGRST116", message: "No rows" } });
    const mockEqUser = vi.fn().mockReturnValue({ single: mockSingle });
    const mockEqId = vi.fn().mockReturnValue({ eq: mockEqUser });
    const mockSelect = vi.fn().mockReturnValue({ eq: mockEqId });
    mockSupabase.from.mockReturnValue({ select: mockSelect });
    mockCreateSupabaseServerClient.mockResolvedValue(mockSupabase as never);

    const result = await testWebhook(mockWebhookId);

    expect(result).toEqual({
      success: false,
      error: "Webhook not found",
    });
  });

  it("successfully tests webhook and returns success status", async () => {
    const mockSupabase = createMockSupabase({ user: { id: mockUserId } });
    const mockWebhook = {
      id: mockWebhookId,
      url: "https://example.com/webhook",
      secret: "whsec_1234567890abcdef1234567890abcdef",
      enabled: true,
    };
    const mockSingle = vi.fn().mockResolvedValue({ data: mockWebhook, error: null });
    const mockEqUser = vi.fn().mockReturnValue({ single: mockSingle });
    const mockEqId = vi.fn().mockReturnValue({ eq: mockEqUser });
    const mockSelect = vi.fn().mockReturnValue({ eq: mockEqId });
    mockSupabase.from.mockReturnValue({ select: mockSelect });
    mockCreateSupabaseServerClient.mockResolvedValue(mockSupabase as never);

    // Mock successful fetch response
    const mockResponse = { status: 200, ok: true };
    vi.mocked(global.fetch).mockResolvedValue(mockResponse as Response);

    const result = await testWebhook(mockWebhookId);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.status_code).toBe(200);
      expect(result.data.success).toBe(true);
      expect(result.data.response_time_ms).toBeGreaterThanOrEqual(0);
    }

    // Verify fetch was called with correct headers
    expect(global.fetch).toHaveBeenCalledWith(
      "https://example.com/webhook",
      expect.objectContaining({
        method: "POST",
        headers: expect.objectContaining({
          "Content-Type": "application/json",
          "X-Webhook-Event": "test",
          "User-Agent": "MacroCalendar-Webhook/1.0",
        }),
      })
    );
  });

  it("returns failure status for non-OK response", async () => {
    const mockSupabase = createMockSupabase({ user: { id: mockUserId } });
    const mockWebhook = {
      id: mockWebhookId,
      url: "https://example.com/webhook",
      secret: "whsec_1234567890abcdef1234567890abcdef",
      enabled: true,
    };
    const mockSingle = vi.fn().mockResolvedValue({ data: mockWebhook, error: null });
    const mockEqUser = vi.fn().mockReturnValue({ single: mockSingle });
    const mockEqId = vi.fn().mockReturnValue({ eq: mockEqUser });
    const mockSelect = vi.fn().mockReturnValue({ eq: mockEqId });
    mockSupabase.from.mockReturnValue({ select: mockSelect });
    mockCreateSupabaseServerClient.mockResolvedValue(mockSupabase as never);

    // Mock 500 error response
    const mockResponse = { status: 500, ok: false };
    vi.mocked(global.fetch).mockResolvedValue(mockResponse as Response);

    const result = await testWebhook(mockWebhookId);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.status_code).toBe(500);
      expect(result.data.success).toBe(false);
    }
  });

  it("handles network error gracefully", async () => {
    const mockSupabase = createMockSupabase({ user: { id: mockUserId } });
    const mockWebhook = {
      id: mockWebhookId,
      url: "https://example.com/webhook",
      secret: "whsec_1234567890abcdef1234567890abcdef",
      enabled: true,
    };
    const mockSingle = vi.fn().mockResolvedValue({ data: mockWebhook, error: null });
    const mockEqUser = vi.fn().mockReturnValue({ single: mockSingle });
    const mockEqId = vi.fn().mockReturnValue({ eq: mockEqUser });
    const mockSelect = vi.fn().mockReturnValue({ eq: mockEqId });
    mockSupabase.from.mockReturnValue({ select: mockSelect });
    mockCreateSupabaseServerClient.mockResolvedValue(mockSupabase as never);

    // Mock network error
    vi.mocked(global.fetch).mockRejectedValue(new Error("Network error"));

    const result = await testWebhook(mockWebhookId);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.status_code).toBe(0);
      expect(result.data.success).toBe(false);
    }
  });

  it("handles timeout error gracefully", async () => {
    const mockSupabase = createMockSupabase({ user: { id: mockUserId } });
    const mockWebhook = {
      id: mockWebhookId,
      url: "https://example.com/webhook",
      secret: "whsec_1234567890abcdef1234567890abcdef",
      enabled: true,
    };
    const mockSingle = vi.fn().mockResolvedValue({ data: mockWebhook, error: null });
    const mockEqUser = vi.fn().mockReturnValue({ single: mockSingle });
    const mockEqId = vi.fn().mockReturnValue({ eq: mockEqUser });
    const mockSelect = vi.fn().mockReturnValue({ eq: mockEqId });
    mockSupabase.from.mockReturnValue({ select: mockSelect });
    mockCreateSupabaseServerClient.mockResolvedValue(mockSupabase as never);

    // Mock timeout error
    const timeoutError = new Error("Timeout");
    timeoutError.name = "TimeoutError";
    vi.mocked(global.fetch).mockRejectedValue(timeoutError);

    const result = await testWebhook(mockWebhookId);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.status_code).toBe(0);
      expect(result.data.success).toBe(false);
    }
  });

  it("sends Discord-formatted payload to Discord webhooks", async () => {
    const mockSupabase = createMockSupabase({ user: { id: mockUserId } });
    const mockWebhook = {
      id: mockWebhookId,
      url: "https://discord.com/api/webhooks/1234567890/abcdefghijklmnop",
      secret: "whsec_1234567890abcdef1234567890abcdef",
      enabled: true,
    };
    const mockSingle = vi.fn().mockResolvedValue({ data: mockWebhook, error: null });
    const mockEqUser = vi.fn().mockReturnValue({ single: mockSingle });
    const mockEqId = vi.fn().mockReturnValue({ eq: mockEqUser });
    const mockSelect = vi.fn().mockReturnValue({ eq: mockEqId });
    mockSupabase.from.mockReturnValue({ select: mockSelect });
    mockCreateSupabaseServerClient.mockResolvedValue(mockSupabase as never);

    // Mock successful fetch response
    const mockResponse = { status: 204, ok: true };
    vi.mocked(global.fetch).mockResolvedValue(mockResponse as Response);

    const result = await testWebhook(mockWebhookId);

    expect(result.success).toBe(true);
    if (result.success) {
      expect(result.data.status_code).toBe(204);
      expect(result.data.success).toBe(true);
    }

    // Verify fetch was called with Discord format (content and embeds)
    expect(global.fetch).toHaveBeenCalledWith(
      "https://discord.com/api/webhooks/1234567890/abcdefghijklmnop",
      expect.objectContaining({
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
      })
    );

    // Verify payload contains Discord-specific fields
    const callArgs = vi.mocked(global.fetch).mock.calls[0];
    const requestBody = JSON.parse(callArgs[1]?.body as string);
    expect(requestBody).toHaveProperty("content");
    expect(requestBody).toHaveProperty("embeds");
    expect(requestBody.embeds[0]).toHaveProperty("title");
    expect(requestBody.embeds[0]).toHaveProperty("description");
  });

  it("sends Discord-formatted payload to discordapp.com webhooks", async () => {
    const mockSupabase = createMockSupabase({ user: { id: mockUserId } });
    const mockWebhook = {
      id: mockWebhookId,
      url: "https://discordapp.com/api/webhooks/1234567890/abcdefghijklmnop",
      secret: "whsec_1234567890abcdef1234567890abcdef",
      enabled: true,
    };
    const mockSingle = vi.fn().mockResolvedValue({ data: mockWebhook, error: null });
    const mockEqUser = vi.fn().mockReturnValue({ single: mockSingle });
    const mockEqId = vi.fn().mockReturnValue({ eq: mockEqUser });
    const mockSelect = vi.fn().mockReturnValue({ eq: mockEqId });
    mockSupabase.from.mockReturnValue({ select: mockSelect });
    mockCreateSupabaseServerClient.mockResolvedValue(mockSupabase as never);

    // Mock successful fetch response
    const mockResponse = { status: 204, ok: true };
    vi.mocked(global.fetch).mockResolvedValue(mockResponse as Response);

    const result = await testWebhook(mockWebhookId);

    expect(result.success).toBe(true);

    // Verify payload contains Discord-specific fields
    const callArgs = vi.mocked(global.fetch).mock.calls[0];
    const requestBody = JSON.parse(callArgs[1]?.body as string);
    expect(requestBody).toHaveProperty("content");
    expect(requestBody).toHaveProperty("embeds");
  });

  it("does not treat non-Discord URLs as Discord webhooks", async () => {
    const mockSupabase = createMockSupabase({ user: { id: mockUserId } });
    const mockWebhook = {
      id: mockWebhookId,
      url: "https://discord.example.com/webhook",
      secret: "whsec_1234567890abcdef1234567890abcdef",
      enabled: true,
    };
    const mockSingle = vi.fn().mockResolvedValue({ data: mockWebhook, error: null });
    const mockEqUser = vi.fn().mockReturnValue({ single: mockSingle });
    const mockEqId = vi.fn().mockReturnValue({ eq: mockEqUser });
    const mockSelect = vi.fn().mockReturnValue({ eq: mockEqId });
    mockSupabase.from.mockReturnValue({ select: mockSelect });
    mockCreateSupabaseServerClient.mockResolvedValue(mockSupabase as never);

    // Mock successful fetch response
    const mockResponse = { status: 200, ok: true };
    vi.mocked(global.fetch).mockResolvedValue(mockResponse as Response);

    await testWebhook(mockWebhookId);

    // Verify payload contains standard format, not Discord format
    const callArgs = vi.mocked(global.fetch).mock.calls[0];
    const requestBody = JSON.parse(callArgs[1]?.body as string);
    expect(requestBody).toHaveProperty("event", "test");
    expect(requestBody).toHaveProperty("data");
    expect(requestBody).not.toHaveProperty("content");
    expect(requestBody).not.toHaveProperty("embeds");
  });
});

describe("URL validation", () => {
  beforeEach(() => {
    vi.clearAllMocks();
    // Reset NODE_ENV to test
    vi.stubEnv("NODE_ENV", "test");
  });

  it("rejects non-HTTPS URLs", async () => {
    const result = await createWebhook({ url: "http://example.com/webhook" });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("Webhook URL must use HTTPS");
    }
  });

  it("allows localhost in non-production environment", async () => {
    vi.stubEnv("NODE_ENV", "development");
    const mockSupabase = createMockSupabase({ user: { id: mockUserId } });
    const mockCreatedWebhook = {
      id: mockWebhookId,
      url: "https://localhost:3000/webhook",
      events: ["release.published"],
      enabled: true,
      created_at: "2026-01-11T00:00:00Z",
    };
    const mockSingle = vi
      .fn()
      .mockResolvedValue({ data: mockCreatedWebhook, error: null });
    const mockSelectReturn = vi.fn().mockReturnValue({ single: mockSingle });
    const mockInsert = vi.fn().mockReturnValue({ select: mockSelectReturn });
    mockSupabase.from.mockReturnValue({ insert: mockInsert });
    mockCreateSupabaseServerClient.mockResolvedValue(mockSupabase as never);

    const result = await createWebhook({ url: "https://localhost:3000/webhook" });

    // Should succeed in development
    expect(result.success).toBe(true);
  });

  it("rejects localhost in production environment", async () => {
    vi.stubEnv("NODE_ENV", "production");

    const result = await createWebhook({ url: "https://localhost:3000/webhook" });

    expect(result.success).toBe(false);
    if (!result.success) {
      expect(result.error).toBe("Local/internal webhook hostnames are not allowed in production");
    }
  });

  it("rejects loopback/private IPs in production environment", async () => {
    vi.stubEnv("NODE_ENV", "production");

    const loopback = await createWebhook({ url: "https://127.0.0.1/webhook" });
    expect(loopback.success).toBe(false);
    if (!loopback.success) {
      expect(loopback.error).toBe("Private or loopback IP addresses are not allowed in production");
    }

    const privateIp = await createWebhook({ url: "https://10.0.0.1/webhook" });
    expect(privateIp.success).toBe(false);
    if (!privateIp.success) {
      expect(privateIp.error).toBe("Private or loopback IP addresses are not allowed in production");
    }
  });
});
