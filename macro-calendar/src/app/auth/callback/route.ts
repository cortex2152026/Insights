import { NextResponse, type NextRequest } from "next/server";
import { createSupabaseServerClient } from "@/lib/supabase/server";
import { reportError } from "@/lib/observability";

/**
 * Validates that a redirect path is a safe relative URL.
 * Prevents open redirect vulnerabilities by ensuring the path:
 * - Starts with a single slash (relative path)
 * - Does not start with // (protocol-relative URL)
 * - Does not contain URL schemes (e.g., javascript:, data:)
 *
 * Decodes the path first to prevent encoding bypass attacks.
 */
function isValidRedirectPath(path: string): boolean {
  // Must be a non-empty string
  if (!path || typeof path !== "string") {
    return false;
  }

  // Decode the path to catch encoded bypass attempts (e.g., %6A%61%76%61%73%63%72%69%70%74%3A)
  let decodedPath: string;
  try {
    decodedPath = decodeURIComponent(path);
  } catch {
    // If decoding fails, the path is invalid
    return false;
  }

  // Must start with exactly one slash (relative path)
  if (!decodedPath.startsWith("/") || decodedPath.startsWith("//")) {
    return false;
  }

  // Block dangerous URL schemes (check both original and decoded)
  const lowerPath = decodedPath.toLowerCase();
  const dangerousSchemes = ["javascript:", "data:", "vbscript:", "file:"];
  for (const scheme of dangerousSchemes) {
    if (lowerPath.includes(scheme)) {
      return false;
    }
  }

  return true;
}

/**
 * Auth callback route handler for Supabase magic link authentication.
 *
 * When a user clicks a magic link in their email, Supabase redirects to this route
 * with a `code` parameter. This handler exchanges the code for a session and
 * redirects the user to the home page.
 *
 * See: https://supabase.com/docs/guides/auth/server-side/nextjs
 */
export async function GET(request: NextRequest) {
  const { searchParams, origin } = new URL(request.url);
  const code = searchParams.get("code");
  const nextParam = searchParams.get("next") ?? "/";

  // Validate redirect path to prevent open redirect attacks
  const next = isValidRedirectPath(nextParam) ? nextParam : "/";

  // If no code is provided, redirect to home with error
  if (!code) {
    return NextResponse.redirect(`${origin}/?error=missing_code`);
  }

  // Use the shared Supabase server client utility
  const supabase = await createSupabaseServerClient();

  // Exchange the code for a session
  const { error } = await supabase.auth.exchangeCodeForSession(code);

  if (error) {
    reportError(error, {
      event: "auth_callback_exchange_failed",
      route: "/auth/callback",
    });

    // If the code was already used or expired, the user might already be logged in
    // from a previous attempt. Check if we have a valid session.
    const {
      data: { user },
    } = await supabase.auth.getUser();
    if (user) {
      return NextResponse.redirect(`${origin}${next}`);
    }

    return NextResponse.redirect(`${origin}/?error=auth_failed`);
  }

  // Success - redirect to the intended destination (defaults to home)
  return NextResponse.redirect(`${origin}${next}`);
}
