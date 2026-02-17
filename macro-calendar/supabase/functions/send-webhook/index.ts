/**
 * Edge Function: send-webhook
 * Task: T303
 *
 * Triggered alongside email alerts when releases are published or revised.
 * Queries users with webhook endpoints subscribed to the event type.
 * Signs payload with HMAC-SHA256 and delivers with retry logic.
 */

import { createClient } from "npm:@supabase/supabase-js@2";

// Type definitions for webhook payload from database trigger
interface Release {
  id: string;
  indicator_id: string;
  release_at: string;
  period: string;
  actual: string | null;
  forecast: string | null;
  previous: string | null;
  revised: string | null;
  unit: string | null;
  notes: string | null;
  created_at: string;
  revision_history?: RevisionEntry[];
}

interface RevisionEntry {
  previous_actual: string | null;
  new_actual: string;
  revised_at: string;
}

interface WebhookPayload {
  type: "INSERT" | "UPDATE" | "DELETE";
  table: string;
  schema: string;
  record: Release;
  old_record: Release | null;
}

// Type for indicator data
interface Indicator {
  id: string;
  name: string;
  country_code: string;
  category: string;
  source_name: string;
}

// Type for webhook endpoint from database
interface WebhookEndpoint {
  id: string;
  user_id: string;
  url: string;
  secret: string;
  events: string[];
  enabled: boolean;
}

// Webhook event types
type WebhookEventType = "release.published" | "release.revised";

// Validate required environment variables
const SUPABASE_URL = Deno.env.get("SUPABASE_URL");
const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY");
const ENV_VARS_VALID = SUPABASE_URL && SUPABASE_SERVICE_ROLE_KEY;

if (!ENV_VARS_VALID) {
  console.error("Missing required environment variables: SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY");
}

// Create Supabase client with service role key for admin access
// Note: Client is created even if env vars are missing to avoid module load errors,
// but requests will fail if env vars are not properly set
const supabase = createClient(
  SUPABASE_URL ?? "",
  SUPABASE_SERVICE_ROLE_KEY ?? ""
);

const APP_URL = Deno.env.get("APP_URL") || "https://macrocalendar.com";

// Retry configuration
const MAX_RETRIES = 3;
const INITIAL_BACKOFF_MS = 1000; // 1 second
const REQUEST_TIMEOUT_MS = 10000; // 10 seconds
const MAX_RESPONSE_BODY_LENGTH = 1024; // Truncate response body for storage

// Discord embed color - 0x58C7FF (blue) in decimal = 5818367
const DISCORD_EMBED_COLOR = 5818367;

function isIpv4(value: string): boolean {
  const parts = value.split(".");
  if (parts.length !== 4) return false;
  return parts.every((part) => {
    if (!/^\d+$/.test(part)) return false;
    const n = Number(part);
    return n >= 0 && n <= 255;
  });
}

function isIpv6(value: string): boolean {
  // Lightweight check (enough for routing decisions)
  return value.includes(":");
}

function isPrivateOrUnsafeIp(ip: string): boolean {
  const normalized = ip.toLowerCase();

  // IPv4-mapped IPv6
  if (normalized.startsWith("::ffff:")) {
    const mapped = normalized.replace("::ffff:", "");
    return isPrivateOrUnsafeIp(mapped);
  }

  if (isIpv4(normalized)) {
    const [a, b] = normalized.split(".").map(Number);

    if (a === 10) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 0) return true;

    return false;
  }

  if (isIpv6(normalized)) {
    if (normalized === "::1" || normalized === "::") return true;
    if (normalized.startsWith("fe80:")) return true;
    if (normalized.startsWith("fc") || normalized.startsWith("fd")) return true;
    return false;
  }

  return false;
}

async function resolveHostnameIps(hostname: string): Promise<string[]> {
  const out = new Set<string>();

  try {
    const a = await Deno.resolveDns(hostname, "A");
    for (const entry of a) out.add(String(entry));
  } catch {
    // ignore
  }

  try {
    const aaaa = await Deno.resolveDns(hostname, "AAAA");
    for (const entry of aaaa) out.add(String(entry));
  } catch {
    // ignore
  }

  return [...out];
}

async function validateOutboundWebhookUrl(url: string): Promise<{ valid: true } | { valid: false; error: string }> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch {
    return { valid: false, error: "Invalid webhook URL" };
  }

  if (parsed.protocol !== "https:") {
    return { valid: false, error: "Webhook URL must use HTTPS" };
  }

  const hostname = parsed.hostname.toLowerCase();

  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal")
  ) {
    return { valid: false, error: "Local/internal webhook hostnames are blocked" };
  }

  if ((isIpv4(hostname) || isIpv6(hostname)) && isPrivateOrUnsafeIp(hostname)) {
    return { valid: false, error: "Private/internal webhook IP addresses are blocked" };
  }

  if (!isIpv4(hostname) && !isIpv6(hostname)) {
    const resolvedIps = await resolveHostnameIps(hostname);
    if (resolvedIps.length === 0) {
      return { valid: false, error: "Webhook hostname could not be resolved" };
    }
    if (resolvedIps.some((ip) => isPrivateOrUnsafeIp(ip))) {
      return { valid: false, error: "Webhook hostname resolves to private/internal IP" };
    }
  }

  return { valid: true };
}

/**
 * Determine if a request should be retried based on status code.
 * - 2xx: Success, no retry needed
 * - 4xx (except 429): Client error, don't retry
 * - 429: Rate limited, retry with backoff
 * - 5xx: Server error, retry with backoff
 */
function shouldRetry(statusCode: number): boolean {
  // Success - no retry needed
  if (statusCode >= 200 && statusCode < 300) {
    return false;
  }
  // Client errors (except rate limiting) - don't retry
  if (statusCode >= 400 && statusCode < 500 && statusCode !== 429) {
    return false;
  }
  // Server errors (5xx) and rate limiting (429) - retry
  return true;
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
 * Create HMAC-SHA256 signature for webhook payload.
 */
async function createSignature(
  payload: string,
  secret: string
): Promise<string> {
  const encoder = new TextEncoder();
  const keyData = encoder.encode(secret);
  const payloadData = encoder.encode(payload);

  const cryptoKey = await crypto.subtle.importKey(
    "raw",
    keyData,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const signature = await crypto.subtle.sign("HMAC", cryptoKey, payloadData);
  const signatureArray = new Uint8Array(signature);

  // Convert to hex string
  return Array.from(signatureArray)
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * Sleep for specified milliseconds.
 */
function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

/**
 * Truncate a string to a maximum length, appending "..." if truncated.
 */
function truncateString(str: string, maxLength: number): string {
  if (str.length <= maxLength) {
    return str;
  }
  return str.slice(0, maxLength - 3) + "...";
}

/**
 * Log a webhook delivery attempt to the webhook_deliveries table.
 */
async function logDeliveryAttempt(
  webhookId: string,
  eventType: string,
  payload: object,
  responseCode: number | null,
  responseBody: string | null
): Promise<void> {
  try {
    const { error } = await supabase.from("webhook_deliveries").insert({
      webhook_id: webhookId,
      event_type: eventType,
      payload: payload,
      response_code: responseCode,
      response_body: responseBody
        ? truncateString(responseBody, MAX_RESPONSE_BODY_LENGTH)
        : null,
    });

    if (error) {
      console.error("Failed to log webhook delivery:", error);
    }
  } catch (err) {
    console.error("Error logging webhook delivery:", err);
  }
}

/**
 * Create standard webhook payload for release events.
 */
function createStandardPayload(
  eventType: WebhookEventType,
  indicator: Indicator,
  release: Release
): object {
  return {
    event: eventType,
    timestamp: new Date().toISOString(),
    data: {
      indicator: {
        id: indicator.id,
        name: indicator.name,
        country: indicator.country_code,
        category: indicator.category,
        source: indicator.source_name,
      },
      release: {
        id: release.id,
        scheduled_at: release.release_at,
        period: release.period,
        actual: release.actual,
        forecast: release.forecast,
        previous: release.previous,
        revised: release.revised,
        unit: release.unit,
        notes: release.notes,
      },
    },
  };
}

/**
 * Create Discord-formatted payload for release events.
 */
function createDiscordPayload(
  eventType: WebhookEventType,
  indicator: Indicator,
  release: Release
): object {
  const eventTitle =
    eventType === "release.published"
      ? "📊 New Release Published"
      : "📝 Release Revised";

  const actualValue = release.actual
    ? `${release.actual}${release.unit ? ` ${release.unit}` : ""}`
    : "Pending";
  const forecastValue = release.forecast
    ? `${release.forecast}${release.unit ? ` ${release.unit}` : ""}`
    : "N/A";
  const previousValue = release.previous
    ? `${release.previous}${release.unit ? ` ${release.unit}` : ""}`
    : "N/A";

  return {
    content: `🔔 **${eventTitle}**`,
    embeds: [
      {
        title: indicator.name,
        description: `${indicator.country_code} • ${indicator.category}`,
        url: `${APP_URL}/indicator/${indicator.id}`,
        color: DISCORD_EMBED_COLOR,
        fields: [
          {
            name: "📅 Period",
            value: release.period,
            inline: true,
          },
          {
            name: "📈 Actual",
            value: actualValue,
            inline: true,
          },
          {
            name: "🎯 Forecast",
            value: forecastValue,
            inline: true,
          },
          {
            name: "📉 Previous",
            value: previousValue,
            inline: true,
          },
        ],
        footer: {
          text: "Macro Calendar",
        },
        timestamp: new Date().toISOString(),
      },
    ],
  };
}

/**
 * Deliver webhook to a single endpoint with retry logic.
 * Returns delivery result with status and attempt count.
 * Logs delivery attempt to webhook_deliveries table.
 */
async function deliverWebhook(
  endpoint: WebhookEndpoint,
  eventType: WebhookEventType,
  indicator: Indicator,
  release: Release
): Promise<{
  endpoint_id: string;
  success: boolean;
  status_code: number | null;
  attempts: number;
  error?: string;
}> {
  const isDiscord = isDiscordWebhook(endpoint.url);

  // Create appropriate payload based on webhook type
  const payload = isDiscord
    ? createDiscordPayload(eventType, indicator, release)
    : createStandardPayload(eventType, indicator, release);

  const payloadString = JSON.stringify(payload);

  // Re-validate outbound target at delivery time to reduce SSRF/DNS-rebinding risk.
  const outboundValidation = await validateOutboundWebhookUrl(endpoint.url);
  if (!outboundValidation.valid) {
    await logDeliveryAttempt(
      endpoint.id,
      eventType,
      payload,
      null,
      outboundValidation.error
    );

    return {
      endpoint_id: endpoint.id,
      success: false,
      status_code: null,
      attempts: 1,
      error: outboundValidation.error,
    };
  }

  // Build headers - Discord doesn't use custom webhook headers
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (!isDiscord) {
    const signature = await createSignature(payloadString, endpoint.secret);
    headers["X-Webhook-Signature"] = `sha256=${signature}`;
    headers["X-Webhook-Event"] = eventType;
    headers["X-Webhook-Id"] = endpoint.id;
    headers["User-Agent"] = "MacroCalendar-Webhook/1.0";
  }

  let lastError: string | undefined;
  let lastStatusCode: number | null = null;
  let lastResponseBody: string | null = null;

  // Retry loop with exponential backoff
  for (let attempt = 1; attempt <= MAX_RETRIES; attempt++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(
        () => controller.abort(),
        REQUEST_TIMEOUT_MS
      );

      const response = await fetch(endpoint.url, {
        method: "POST",
        headers,
        body: payloadString,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);
      lastStatusCode = response.status;

      // Try to read response body for logging
      try {
        lastResponseBody = await response.text();
      } catch {
        lastResponseBody = null;
      }

      // Success: 2xx response
      if (response.ok) {
        // Update last_triggered_at timestamp
        await supabase
          .from("webhook_endpoints")
          .update({ last_triggered_at: new Date().toISOString() })
          .eq("id", endpoint.id);

        // Log successful delivery
        await logDeliveryAttempt(
          endpoint.id,
          eventType,
          payload,
          response.status,
          lastResponseBody
        );

        return {
          endpoint_id: endpoint.id,
          success: true,
          status_code: response.status,
          attempts: attempt,
        };
      }

      // Check if we should retry based on status code
      lastError = `HTTP ${response.status}`;
      if (!shouldRetry(response.status)) {
        break;
      }
    } catch (error) {
      if (error instanceof Error) {
        if (error.name === "AbortError") {
          lastError = "Request timeout";
          lastResponseBody = "Request timed out";
        } else {
          lastError = error.message;
          lastResponseBody = error.message;
        }
      } else {
        lastError = String(error);
        lastResponseBody = String(error);
      }
    }

    // Wait before next retry (exponential backoff)
    if (attempt < MAX_RETRIES) {
      const backoffMs = INITIAL_BACKOFF_MS * Math.pow(2, attempt - 1);
      console.log(
        `Webhook delivery attempt ${attempt} failed for endpoint ${endpoint.id}, retrying in ${backoffMs}ms...`
      );
      await sleep(backoffMs);
    }
  }

  // All retries failed - log the final failure
  await logDeliveryAttempt(
    endpoint.id,
    eventType,
    payload,
    lastStatusCode,
    lastResponseBody ?? lastError ?? null
  );

  return {
    endpoint_id: endpoint.id,
    success: false,
    status_code: lastStatusCode,
    attempts: MAX_RETRIES,
    error: lastError,
  };
}

/**
 * Get all enabled webhook endpoints subscribed to the given event type.
 * Uses service role to bypass RLS (we need to query across all users).
 */
async function getWebhookEndpoints(
  eventType: WebhookEventType
): Promise<WebhookEndpoint[]> {
  // Query all enabled webhook endpoints and filter by event type in code
  // This approach is more reliable than using .contains() in Edge Functions
  // because the PostgREST array containment operator can have edge cases
  const { data, error } = await supabase
    .from("webhook_endpoints")
    .select("id, user_id, url, secret, events, enabled")
    .eq("enabled", true);

  if (error) {
    console.error("Failed to fetch webhook endpoints:", error);
    return [];
  }

  console.log(`Fetched ${data?.length ?? 0} enabled webhook endpoints from database`);

  // Filter endpoints that are subscribed to this event type
  const endpoints = (data as WebhookEndpoint[]) ?? [];
  const filtered = endpoints.filter((endpoint) => endpoint.events.includes(eventType));

  console.log(`Filtered to ${filtered.length} endpoints subscribed to ${eventType}`);

  return filtered;
}

/**
 * Determine the event type based on the database operation.
 * INSERT = release.published
 * UPDATE with actual value change = release.revised
 *
 * Note: A revision only triggers when:
 * - The old actual value was not null (value existed before)
 * - The new actual value is different from the old value
 * - The new actual value is not null (value is not being cleared)
 */
function determineEventType(
  payload: WebhookPayload
): WebhookEventType | null {
  if (payload.type === "INSERT") {
    return "release.published";
  }

  if (payload.type === "UPDATE") {
    // Check if actual value was updated (revision)
    const oldActual = payload.old_record?.actual;
    const newActual = payload.record.actual;

    // A revision occurs when:
    // 1. There was a previous actual value (oldActual !== null)
    // 2. The new value is different from the old value
    // 3. The new value is not null (we're not just clearing the value)
    // Note: Initial actual value being set (null -> value) is handled by INSERT trigger
    if (oldActual !== null && newActual !== null && newActual !== oldActual) {
      return "release.revised";
    }
  }

  return null;
}

Deno.serve(async (req) => {
  // Only allow POST requests (webhook calls from database triggers)
  if (req.method !== "POST") {
    return new Response(JSON.stringify({ error: "Method not allowed" }), {
      status: 405,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Check environment variables before processing
  if (!ENV_VARS_VALID) {
    return new Response(
      JSON.stringify({ error: "Server configuration error: missing environment variables" }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" },
      }
    );
  }

  try {
    const payload: WebhookPayload = await req.json();

    // Determine event type
    const eventType = determineEventType(payload);
    if (!eventType) {
      return new Response(
        JSON.stringify({
          message: "Ignored: not a webhook-triggering event",
          type: payload.type,
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    const release = payload.record;
    console.log(
      `Processing webhook delivery for ${eventType}, indicator_id: ${release.indicator_id}`
    );

    // Fetch indicator details
    const { data: indicator, error: indicatorError } = await supabase
      .from("indicators")
      .select("id, name, country_code, category, source_name")
      .eq("id", release.indicator_id)
      .single();

    if (indicatorError || !indicator) {
      console.error("Failed to fetch indicator:", indicatorError);
      return new Response(JSON.stringify({ error: "Indicator not found" }), {
        status: 404,
        headers: { "Content-Type": "application/json" },
      });
    }

    // Get all webhook endpoints subscribed to this event type
    const endpoints = await getWebhookEndpoints(eventType);

    if (endpoints.length === 0) {
      console.log(`No webhook endpoints found for event type: ${eventType}`);
      return new Response(
        JSON.stringify({
          message: "No webhook endpoints to notify",
          event_type: eventType,
          delivered: 0,
        }),
        {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    console.log(
      `Found ${endpoints.length} webhook endpoint(s) for ${eventType}`
    );

    // Deliver webhooks to all endpoints in parallel
    const results = await Promise.all(
      endpoints.map((endpoint) =>
        deliverWebhook(endpoint, eventType, indicator as Indicator, release)
      )
    );

    const delivered = results.filter((r) => r.success).length;
    const failed = results.filter((r) => !r.success).length;

    console.log(`Webhooks delivered: ${delivered}, failed: ${failed}`);

    return new Response(
      JSON.stringify({
        message: "Webhook delivery processed",
        event_type: eventType,
        indicator_id: release.indicator_id,
        release_id: release.id,
        delivered,
        failed,
        results,
      }),
      {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }
    );
  } catch (error) {
    console.error("Unexpected error:", error);
    return new Response(
      JSON.stringify({
        error: "Internal server error",
        details: String(error),
      }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
});
