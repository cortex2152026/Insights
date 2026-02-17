-- Migration: Harden privileges on audit_log and request_logs
-- Description: Explicitly revoke access from anon/authenticated and grant least privilege to service_role
-- Date: 2026-02-17
-- Task: Ship-this-week security hardening

-- Ensure no broad/default access remains
REVOKE ALL ON TABLE public.audit_log FROM PUBLIC;
REVOKE ALL ON TABLE public.request_logs FROM PUBLIC;

-- Explicitly deny direct access from user-facing roles
REVOKE ALL ON TABLE public.audit_log FROM anon, authenticated;
REVOKE ALL ON TABLE public.request_logs FROM anon, authenticated;

-- Service role is the only application role that should read/write these tables
GRANT SELECT, INSERT ON TABLE public.audit_log TO service_role;
GRANT SELECT, INSERT ON TABLE public.request_logs TO service_role;

-- Do not grant UPDATE/DELETE to keep logs append-only at app level
COMMENT ON TABLE public.audit_log IS 'Audit trail of admin actions. No RLS by design; access restricted to service_role via explicit grants.';
COMMENT ON TABLE public.request_logs IS 'Request logs for abuse detection/API usage. No RLS by design; access restricted to service_role via explicit grants.';
