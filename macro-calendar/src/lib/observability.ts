type ErrorContext = Record<string, unknown>;

/**
 * Lightweight structured error reporting.
 * Keeps logs machine-parseable and can be shipped to external observability providers.
 */
export function reportError(error: unknown, context: ErrorContext = {}): void {
  const normalized =
    error instanceof Error
      ? { message: error.message, name: error.name, stack: error.stack }
      : { message: String(error) };

  console.error(
    JSON.stringify({
      level: "error",
      event: "app_error",
      ...context,
      error: normalized,
      timestamp: new Date().toISOString(),
    })
  );
}
