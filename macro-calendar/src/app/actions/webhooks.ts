"use server";

import { createSupabaseServerClient } from "@/lib/supabase/server";
import { randomBytes } from "crypto";
import { lookup } from "dns/promises";
import net from "net";
import { z } from "zod";

// Valid event types for webhook subscriptions
const VALID_EVENT_TYPES = ["release.published", "release.revised"] as const;
type WebhookEventType = (typeof VALID_EVENT_TYPES)[number];

/**
 * Check if the app is running in production.
 * Used to enforce HTTPS and block localhost URLs in production.
 */
function isProduction(): boolean {
  return process.env.NODE_ENV === "production";
}

/**
 * Check whether an IP is private/link-local/loopback/otherwise unsafe for webhook egress.
 */
function isPrivateOrUnsafeIp(ip: string): boolean {
  const normalized = ip.toLowerCase();

  // IPv4-mapped IPv6 (e.g., ::ffff:127.0.0.1)
  if (normalized.startsWith("::ffff:")) {
    const mapped = normalized.replace("::ffff:", "");
    return isPrivateOrUnsafeIp(mapped);
  }

  const version = net.isIP(normalized);

  if (version === 4) {
    const [a, b] = normalized.split(".").map(Number);

    // RFC1918 + loopback + link-local + carrier-grade NAT + unspecified
    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 0) return true;

    return false;
  }

  if (version === 6) {
    // loopback, link-local, unique local, unspecified
    if (normalized === "::1" || normalized === "::") return true;
    if (normalized.startsWith("fe80:")) return true;
    if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
    return false;
  }

  return false;
}

async function resolveHostnameIps(hostname: string): Promise<string[]> {
  try {
    const records = await lookup(hostname, { all: true, verbatim: true });
    return [...new Set(records.map((record) => record.address))];
  } catch {
    return [];
  }
}

/**
 * Validate a webhook URL.
 * - Must be a valid URL
 * - Must use HTTPS
 * - Cannot target localhost/private networks in production
 */
async function validateWebhookUrl(url: string): Promise<{ valid: true } | { valid: false; error: string }> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { valid: false, error: "Invalid URL format" };
  }

  // Must use HTTPS
  if (parsed.protocol !== "https:") {
    return { valid: false, error: "Webhook URL must use HTTPS" };
  }

  if (!isProduction()) {
    return { valid: true };
  }

  const hostname = parsed.hostname.toLowerCase();

  // Block obvious local/internal hostnames
  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal")
  ) {
    return { valid: false, error: "Local/internal webhook hostnames are not allowed in production" };
  }

  // Direct IP targets
  if (net.isIP(hostname) && isPrivateOrUnsafeIp(hostname)) {
    return { valid: false, error: "Private or loopback IP addresses are not allowed in production" };
  }

  // DNS resolution check to reduce SSRF risk via public hostname -> private IP
  if (!net.isIP(hostname)) {
    const resolvedIps = await resolveHostnameIps(hostname);
    if (resolvedIps.length === 0) {
      return { valid: false, error: "Webhook hostname could not be resolved" };
    }

    if (resolvedIps.some((ip) => isPrivateOrUnsafeIp(ip))) {
      return { valid: false, error: "Webhook hostname resolves to a private/internal IP" };
    }
  }

  return { valid: true };
}

// Schema for webhook URL validation (base validation, additional checks in validateWebhookUrl)
const webhookUrlSchema = z.string().url("Invalid URL format").max(2048, "URL must be 2048 characters or less");

// Schema for webhook events array
const webhookEventsSchema = z
  .array(z.enum(VALID_EVENT_TYPES))
  .min(1, "At least one event type is required")
  .max(10, "Maximum 10 event types allowed");

// Schema for webhook ID validation
const webhookIdSchema = z.string().uuid("Invalid webhook ID");

// Schema for creating a webhook
const createWebhookSchema = z.object({
  url: webhookUrlSchema,
  events: webhookEventsSchema.optional(),
});

// Schema for updating a webhook
const updateWebhookSchema = z.object({
  url: webhookUrlSchema.optional(),
  events: webhookEventsSchema.optional(),
  enabled: z.boolean().optional(),
});

/**
 * Webhook endpoint record from the database.
 */
export type WebhookEndpoint = {
  id: string;
  url: string;
  /** Masked secret (only first 8 chars shown) */
  secret_preview: string;
  events: WebhookEventType[];
  enabled: boolean;
  created_at: string;
  updated_at: string;
  last_triggered_at: string | null;
};

/**
 * Result type for webhook actions.
 * Success returns data, failure returns error message.
 */
export type WebhookActionResult<T = void> =
  | { success: true; data: T }
  | { success: false; error: string };

/**
 * Generate a cryptographically secure webhook secret.
 * Format: whsec_{32 random hex characters} (38 chars total)
 */
function generateWebhookSecret(): string {
  const randomPart = randomBytes(16).toString("hex");
  return `whsec_${randomPart}`;
}

/**
 * Mask a webhook secret for display.
 * Shows only the prefix for identification.
 */
function maskSecret(secret: string): string {
  if (secret.length <= 10) {
    return "****";
  }
  return secret.slice(0, 10) + "****";
}

/**
 * Get all webhook endpoints for the current user.
 *
 * @returns List of webhook endpoints or error
 */
export async function listWebhooks(): Promise<WebhookActionResult<WebhookEndpoint[]>> {
  const supabase = await createSupabaseServerClient();

  // Get authenticated user
  const {
    data: { user },
    error: authError,
  } = await supabase.auth.getUser();

  if (authError || !user) {
    return { success: false, error: "Not authenticated" };
  }

  // Fetch webhook endpoints for the user (RLS ensures only user's webhooks are returned)
  const { data, error: selectError } = await supabase
    .from("webhook_endpoints")
    .select("id, url, secret, events, enabled, created_at, updated_at, last_triggered_at")
    .eq("user_id", user.id)
    .order("created_at", { ascending: false });

  if (selectError) {
    return { success: false, error: "Failed to fetch webhooks" };
  }

  // Transform data to include masked secret
  const webhooks: WebhookEndpoint[] = (data ?? []).map((webhook) => ({
    id: webhook.id,
    url: webhook.url,
    secret_preview: maskSecret(webhook.secret),
    events: webhook.events as WebhookEventType[],
    enabled: webhook.enabled,
    created_at: webhook.created_at,
    updated_at: webhook.updated_at,
    last_triggered_at: webhook.last_triggered_at,
  }));

  return { success: true, data: webhooks };
}

/**
 * Create a new webhook endpoint for the current user.
 * Returns the plain secret ONLY ONCE - it cannot be retrieved later.
 *
 * @param input - Webhook configuration (url, events)
 * @returns The created webhook (including plain secret shown only once)
 */
export async function createWebhook(input: {
  url: string;
  events?: WebhookEventType[];
}): Promise<
  WebhookActionResult<{
    id: string;
    url: string;
    /** The plain webhook secret - ONLY returned once at creation time */
    secret: string;
    events: WebhookEventType[];
    enabled: boolean;
    created_at: string;
  }>
> {
  // Validate input schema
  const parseResult = createWebhookSchema.safeParse(input);
  if (!parseResult.success) {
    const firstError = parseResult.error.issues[0];
    return {
      success: false,
      error: firstError?.message ?? "Invalid input",
    };
  }

  // Validate URL (HTTPS required, no localhost in production)
  const urlValidation = await validateWebhookUrl(parseResult.data.url);
  if (!urlValidation.valid) {
    return { success: false, error: urlValidation.error };
  }

  const supabase = await createSupabaseServerClient();

  // Get authenticated user
  const {
    data: { user },
    error: authError,
  } = await supabase.auth.getUser();

  if (authError || !user) {
    return { success: false, error: "Not authenticated" };
  }

  // Generate secure webhook secret
  const plainSecret = generateWebhookSecret();
  const events = parseResult.data.events ?? ["release.published"];

  // Insert webhook endpoint into database
  const { data, error: insertError } = await supabase
    .from("webhook_endpoints")
    .insert({
      user_id: user.id,
      url: parseResult.data.url,
      secret: plainSecret,
      events: events,
    })
    .select("id, url, events, enabled, created_at")
    .single();

  if (insertError) {
    return { success: false, error: "Failed to create webhook" };
  }

  return {
    success: true,
    data: {
      id: data.id,
      url: data.url,
      secret: plainSecret,
      events: data.events as WebhookEventType[],
      enabled: data.enabled,
      created_at: data.created_at,
    },
  };
}

/**
 * Update an existing webhook endpoint.
 *
 * @param webhookId - The ID of the webhook to update
 * @param input - Fields to update (url, events, enabled)
 * @returns Updated webhook or error
 */
export async function updateWebhook(
  webhookId: string,
  input: {
    url?: string;
    events?: WebhookEventType[];
    enabled?: boolean;
  }
): Promise<WebhookActionResult<WebhookEndpoint>> {
  // Validate webhook ID
  const idParseResult = webhookIdSchema.safeParse(webhookId);
  if (!idParseResult.success) {
    return { success: false, error: "Invalid webhook ID" };
  }

  // Validate input schema
  const parseResult = updateWebhookSchema.safeParse(input);
  if (!parseResult.success) {
    const firstError = parseResult.error.issues[0];
    return {
      success: false,
      error: firstError?.message ?? "Invalid input",
    };
  }

  // Check if there's anything to update
  const updateData = parseResult.data;
  if (
    updateData.url === undefined &&
    updateData.events === undefined &&
    updateData.enabled === undefined
  ) {
    return { success: false, error: "No fields to update" };
  }

  // Validate URL if provided
  if (updateData.url !== undefined) {
    const urlValidation = await validateWebhookUrl(updateData.url);
    if (!urlValidation.valid) {
      return { success: false, error: urlValidation.error };
    }
  }

  const supabase = await createSupabaseServerClient();

  // Get authenticated user
  const {
    data: { user },
    error: authError,
  } = await supabase.auth.getUser();

  if (authError || !user) {
    return { success: false, error: "Not authenticated" };
  }

  // Check if webhook exists and belongs to user (RLS will enforce this)
  const { data: existing, error: selectError } = await supabase
    .from("webhook_endpoints")
    .select("id")
    .eq("id", webhookId)
    .eq("user_id", user.id)
    .single();

  if (selectError || !existing) {
    if (selectError?.code === "PGRST116") {
      return { success: false, error: "Webhook not found" };
    }
    return { success: false, error: "Failed to find webhook" };
  }

  // Build update object
  const updates: Record<string, unknown> = {};
  if (updateData.url !== undefined) updates.url = updateData.url;
  if (updateData.events !== undefined) updates.events = updateData.events;
  if (updateData.enabled !== undefined) updates.enabled = updateData.enabled;

  // Update the webhook
  const { data: updated, error: updateError } = await supabase
    .from("webhook_endpoints")
    .update(updates)
    .eq("id", webhookId)
    .select("id, url, secret, events, enabled, created_at, updated_at, last_triggered_at")
    .single();

  if (updateError) {
    return { success: false, error: "Failed to update webhook" };
  }

  return {
    success: true,
    data: {
      id: updated.id,
      url: updated.url,
      secret_preview: maskSecret(updated.secret),
      events: updated.events as WebhookEventType[],
      enabled: updated.enabled,
      created_at: updated.created_at,
      updated_at: updated.updated_at,
      last_triggered_at: updated.last_triggered_at,
    },
  };
}

/**
 * Delete a webhook endpoint permanently.
 *
 * @param webhookId - The ID of the webhook to delete
 * @returns Success/failure result
 */
export async function deleteWebhook(webhookId: string): Promise<WebhookActionResult<void>> {
  // Validate webhook ID
  const parseResult = webhookIdSchema.safeParse(webhookId);
  if (!parseResult.success) {
    return { success: false, error: "Invalid webhook ID" };
  }

  const supabase = await createSupabaseServerClient();

  // Get authenticated user
  const {
    data: { user },
    error: authError,
  } = await supabase.auth.getUser();

  if (authError || !user) {
    return { success: false, error: "Not authenticated" };
  }

  // Delete the webhook (RLS ensures user can only delete their own)
  const { error: deleteError } = await supabase
    .from("webhook_endpoints")
    .delete()
    .eq("id", webhookId)
    .eq("user_id", user.id);

  if (deleteError) {
    return { success: false, error: "Failed to delete webhook" };
  }

  return { success: true, data: undefined };
}

// Discord embed color (blue) - 0x58C7FF in decimal
const DISCORD_EMBED_COLOR = 5818367;

/**
 * Discord webhook embed field structure.
 */
interface DiscordEmbedField {
  name: string;
  value: string;
  inline?: boolean;
}

/**
 * Discord webhook embed structure.
 */
interface DiscordEmbed {
  title?: string;
  description?: string;
  color?: number;
  fields?: DiscordEmbedField[];
  footer?: { text: string };
  timestamp?: string;
}

/**
 * Discord webhook payload structure.
 * @see https://discord.com/developers/docs/resources/webhook#execute-webhook
 */
interface DiscordWebhookPayload {
  content?: string;
  embeds?: DiscordEmbed[];
}

/**
 * Check if a URL is a Discord webhook.
 * Discord webhooks have the format: https://discord.com/api/webhooks/... or https://discordapp.com/api/webhooks/...
 */
function isDiscordWebhook(url: string): boolean {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();
    return (
      (hostname === "discord.com" || hostname === "discordapp.com") &&
      parsed.pathname.startsWith("/api/webhooks/")
    );
  } catch {
    return false;
  }
}

/**
 * Create a Discord-formatted test payload.
 * Discord webhooks require `content` or `embeds` fields.
 */
function createDiscordTestPayload(): DiscordWebhookPayload {
  return {
    content: "🔔 **Macro Calendar Webhook Test**",
    embeds: [
      {
        title: "Test Webhook Delivery",
        description: "This is a test webhook delivery from Macro Calendar. Your webhook endpoint is configured correctly!",
        color: DISCORD_EMBED_COLOR,
        fields: [
          {
            name: "📊 Test Indicator",
            value: "US • Test Category",
            inline: true,
          },
          {
            name: "📅 Release",
            value: `Actual: 1.5%\nForecast: 1.4%\nPrevious: 1.3%`,
            inline: true,
          },
        ],
        footer: {
          text: "Macro Calendar • Webhook Test",
        },
        timestamp: new Date().toISOString(),
      },
    ],
  };
}

/**
 * Test a webhook endpoint by sending a sample payload.
 * The sample payload mimics a real release notification.
 * For Discord webhooks, uses Discord's expected format with embeds.
 *
 * @param webhookId - The ID of the webhook to test
 * @returns Success/failure result with response info
 */
export async function testWebhook(
  webhookId: string
): Promise<
  WebhookActionResult<{
    status_code: number;
    response_time_ms: number;
    success: boolean;
  }>
> {
  // Validate webhook ID
  const parseResult = webhookIdSchema.safeParse(webhookId);
  if (!parseResult.success) {
    return { success: false, error: "Invalid webhook ID" };
  }

  const supabase = await createSupabaseServerClient();

  // Get authenticated user
  const {
    data: { user },
    error: authError,
  } = await supabase.auth.getUser();

  if (authError || !user) {
    return { success: false, error: "Not authenticated" };
  }

  // Get webhook details (RLS ensures user can only access their own)
  const { data: webhook, error: selectError } = await supabase
    .from("webhook_endpoints")
    .select("id, url, secret, enabled")
    .eq("id", webhookId)
    .eq("user_id", user.id)
    .single();

  if (selectError || !webhook) {
    if (selectError?.code === "PGRST116") {
      return { success: false, error: "Webhook not found" };
    }
    return { success: false, error: "Failed to find webhook" };
  }

  // Check if this is a Discord webhook
  const isDiscord = isDiscordWebhook(webhook.url);

  // Create appropriate test payload based on webhook type
  const testPayload = isDiscord
    ? createDiscordTestPayload()
    : {
        event: "test",
        timestamp: new Date().toISOString(),
        data: {
          message: "This is a test webhook delivery from Macro Calendar",
          indicator: {
            id: "00000000-0000-0000-0000-000000000000",
            name: "Test Indicator",
            country: "US",
            category: "Test",
          },
          release: {
            id: "00000000-0000-0000-0000-000000000001",
            scheduled_at: new Date().toISOString(),
            actual: "1.5%",
            forecast: "1.4%",
            previous: "1.3%",
          },
        },
      };

  const payloadString = JSON.stringify(testPayload);

  // Build headers - Discord doesn't use custom webhook headers
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (!isDiscord) {
    // Create HMAC signature for non-Discord webhooks
    const { createHmac } = await import("crypto");
    const signature = createHmac("sha256", webhook.secret)
      .update(payloadString)
      .digest("hex");
    headers["X-Webhook-Signature"] = `sha256=${signature}`;
    headers["X-Webhook-Event"] = "test";
    headers["User-Agent"] = "MacroCalendar-Webhook/1.0";
  }

  // Send test request
  const startTime = Date.now();
  try {
    const response = await fetch(webhook.url, {
      method: "POST",
      headers,
      body: payloadString,
      signal: AbortSignal.timeout(10000), // 10 second timeout
    });

    const responseTimeMs = Date.now() - startTime;

    return {
      success: true,
      data: {
        status_code: response.status,
        response_time_ms: responseTimeMs,
        success: response.ok,
      },
    };
  } catch (error) {
    const responseTimeMs = Date.now() - startTime;

    // Handle timeout or network errors
    if (error instanceof Error) {
      if (error.name === "TimeoutError" || error.name === "AbortError") {
        return {
          success: true,
          data: {
            status_code: 0,
            response_time_ms: responseTimeMs,
            success: false,
          },
        };
      }
    }

    return {
      success: true,
      data: {
        status_code: 0,
        response_time_ms: responseTimeMs,
        success: false,
      },
    };
  }
}
