import { createServerClient } from "@supabase/ssr";
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";
import { ipAddress } from "@vercel/functions";
import { NextResponse, type NextRequest, type NextFetchEvent } from "next/server";
import { env, getRateLimitEnv, isRequestLoggingEnabled } from "@/lib/env";
import { logRequest, createLogEntry } from "@/lib/request-logger";

/**
 * Routes that should skip session refresh in middleware.
 * These routes either:
 * - Use alternative authentication mechanisms (e.g., signed tokens)
 * - Need to establish a session first (e.g., auth callback)
 * and should not trigger cookie manipulation that could interfere.
 */
const SKIP_SESSION_REFRESH_ROUTES = ["/unsubscribe", "/auth/callback"];

/**
 * Routes that have stricter rate limits (30 requests/minute).
 * These are user actions that modify data and should be protected from abuse.
 */
const STRICT_RATE_LIMIT_ROUTES = ["/watchlist", "/api/admin"];

/**
 * Rate limiters for different route types (T220).
 * Stored as a single object to ensure atomic initialization.
 * - Public routes: 60 requests per minute
 * - Watchlist/admin routes: 30 requests per minute (stricter)
 */
interface RateLimiters {
  public: Ratelimit;
  strict: Ratelimit;
}
let rateLimiters: RateLimiters | null = null;
let rateLimitInitialized = false;

/**
 * Initialize rate limiters with Upstash Redis.
 * Called once on first request. Returns the rate limiters if enabled, null otherwise.
 * Uses atomic assignment to prevent race conditions in edge runtime.
 */
function initializeRateLimiters(): RateLimiters | null {
  // Return cached result if already initialized
  if (rateLimitInitialized) {
    return rateLimiters;
  }

  const rateLimitEnv = getRateLimitEnv();
  if (!rateLimitEnv) {
    // Rate limiting not configured, mark as initialized with null
    rateLimitInitialized = true;
    return null;
  }

  const redis = new Redis({
    url: rateLimitEnv.url,
    token: rateLimitEnv.token,
  });

  // Create both limiters atomically and assign together
  const newLimiters: RateLimiters = {
    // Public rate limiter: 60 requests per minute
    public: new Ratelimit({
      redis,
      limiter: Ratelimit.slidingWindow(60, "1 m"),
      prefix: "@upstash/ratelimit:public",
      analytics: true,
    }),
    // Strict rate limiter: 30 requests per minute for watchlist actions
    strict: new Ratelimit({
      redis,
      limiter: Ratelimit.slidingWindow(30, "1 m"),
      prefix: "@upstash/ratelimit:strict",
      analytics: true,
    }),
  };

  // Atomic assignment
  rateLimiters = newLimiters;
  rateLimitInitialized = true;
  return rateLimiters;
}

/**
 * Check if a route should skip session refresh.
 */
function shouldSkipSessionRefresh(pathname: string): boolean {
  return SKIP_SESSION_REFRESH_ROUTES.some((route) =>
    pathname.startsWith(route)
  );
}

/**
 * Check if a route should use strict rate limiting.
 */
function shouldUseStrictRateLimit(pathname: string): boolean {
  return STRICT_RATE_LIMIT_ROUTES.some((route) =>
    pathname.startsWith(route)
  );
}

/**
 * Get client identifier for rate limiting.
 * Uses IP address from Vercel, falling back to headers or default for local development.
 */
function getClientIdentifier(request: NextRequest): string {
  // Use @vercel/functions ipAddress for Vercel deployments
  const ip = ipAddress(request);
  if (ip) {
    return ip;
  }

  // Fallback: Try to get real IP from various headers (works with other proxies)
  const forwardedFor = request.headers.get("x-forwarded-for");
  if (forwardedFor) {
    // x-forwarded-for can contain multiple IPs, take the first one (original client)
    return forwardedFor.split(",")[0].trim();
  }

  const realIp = request.headers.get("x-real-ip");
  if (realIp) {
    return realIp;
  }

  // Default for local development
  return "127.0.0.1";
}

/**
 * Create a 429 Too Many Requests response with appropriate headers.
 */
function createRateLimitResponse(reset: number, limit: number): NextResponse {
  // Calculate seconds until rate limit resets
  const retryAfter = Math.ceil((reset - Date.now()) / 1000);

  return NextResponse.json(
    {
      error: "Too many requests",
      message: "Rate limit exceeded. Please try again later.",
    },
    {
      status: 429,
      headers: {
        "Retry-After": String(Math.max(retryAfter, 1)),
        "X-RateLimit-Limit": String(limit),
        "X-RateLimit-Remaining": "0",
        "X-RateLimit-Reset": String(reset),
      },
    }
  );
}

/**
 * Middleware that:
 * 1. Applies rate limiting (T220) - 60/min public, 30/min for watchlist
 * 2. Refreshes Supabase auth session on each request
 * 3. Logs requests for abuse detection (T222)
 * 
 * Note: This is lightweight middleware - it only refreshes session cookies.
 * Actual authentication/authorization checks should happen in server-side code.
 * 
 * See: https://supabase.com/docs/guides/auth/server-side/nextjs
 */
export async function middleware(request: NextRequest, context: NextFetchEvent) {
  const pathname = request.nextUrl.pathname;
  const clientIp = getClientIdentifier(request);

  // --- Rate Limiting (T220) ---
  // Check rate limit before processing the request
  const limiters = initializeRateLimiters();
  let rateLimitInfo: { limit: number; remaining: number; reset: number } | null = null;

  if (limiters) {
    const useStrictLimit = shouldUseStrictRateLimit(pathname);
    const limiter = useStrictLimit ? limiters.strict : limiters.public;

    const { success, pending, reset, limit, remaining } = await limiter.limit(clientIp);

    // Handle analytics in background (important for edge runtime)
    context.waitUntil(pending);

    if (!success) {
      // Log rate-limited request (T222)
      if (isRequestLoggingEnabled()) {
        context.waitUntil(
          logRequest(createLogEntry(clientIp, pathname, 429, null))
        );
      }
      return createRateLimitResponse(reset, limit);
    }

    // Store rate limit info to add headers to final response
    rateLimitInfo = { limit, remaining, reset };
  }

  // --- Session Refresh ---
  // Create a response that we can modify
  let supabaseResponse = NextResponse.next({
    request,
  });

  // Add pathname header for use in layouts that need to know the current route
  // This enables conditional auth checking based on the route
  supabaseResponse.headers.set("x-pathname", pathname);

  // Add rate limit headers if rate limiting is enabled
  if (rateLimitInfo) {
    supabaseResponse.headers.set("X-RateLimit-Limit", String(rateLimitInfo.limit));
    supabaseResponse.headers.set("X-RateLimit-Remaining", String(rateLimitInfo.remaining));
    supabaseResponse.headers.set("X-RateLimit-Reset", String(rateLimitInfo.reset));
  }

  // Skip session refresh for routes that don't require it
  // This prevents cookie manipulation that could interfere with the user's session
  if (shouldSkipSessionRefresh(pathname)) {
    // Do not log here: middleware cannot reliably know final status code.
    return supabaseResponse;
  }

  // Create Supabase client with cookie handling for middleware
  const supabase = createServerClient(
    env.NEXT_PUBLIC_SUPABASE_URL,
    env.NEXT_PUBLIC_SUPABASE_ANON_KEY,
    {
      cookies: {
        getAll() {
          return request.cookies.getAll();
        },
        setAll(cookiesToSet) {
          // Set cookies on the request (for downstream handlers)
          cookiesToSet.forEach(({ name, value }) =>
            request.cookies.set(name, value)
          );
          // Set cookies on the response (to be sent to browser)
          supabaseResponse = NextResponse.next({
            request,
          });
          // Preserve the pathname header when recreating the response
          supabaseResponse.headers.set("x-pathname", pathname);
          // Preserve rate limit headers when recreating the response
          if (rateLimitInfo) {
            supabaseResponse.headers.set("X-RateLimit-Limit", String(rateLimitInfo.limit));
            supabaseResponse.headers.set("X-RateLimit-Remaining", String(rateLimitInfo.remaining));
            supabaseResponse.headers.set("X-RateLimit-Reset", String(rateLimitInfo.reset));
          }
          cookiesToSet.forEach(({ name, value, options }) =>
            supabaseResponse.cookies.set(name, value, options)
          );
        },
      },
    }
  );

  // Refresh session by calling getUser()
  // IMPORTANT: Do not remove this call - it refreshes the session cookie
  // Do not run code between createServerClient and getUser() to avoid
  // hard-to-debug issues with users being randomly logged out.
  // 
  // NOTE: We use getUser() instead of getClaims() because:
  // - getUser() makes a request to Supabase Auth to refresh the token
  // - getClaims() only validates the JWT locally and does NOT refresh tokens
  // See: https://supabase.com/docs/guides/auth/server-side/creating-a-client
  await supabase.auth.getUser();

  // Request logging is handled at route/action level where real response status is known.
  return supabaseResponse;
}

/**
 * Configure which routes the middleware runs on.
 * Excludes static files and Next.js internals.
 */
export const config = {
  matcher: [
    /*
     * Match all request paths except for:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public files (images, etc.)
     */
    "/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)",
  ],
};
