# Offline security regression checks

Run from the repository root:

```sh
python3 -m unittest discover -s tests -v
node tests/frontend-security.cjs
```

Tests execute current source with isolated DOM/API/GUI/network doubles. They make
no production requests or LAN scans. Python tests extract selected functions to
avoid the Agent's import-time user-directory and GUI setup.

Coverage: stale dashboard/pairing responses, logout state and DOM cleanup, MFA
last-factor/AAL guards, mobile sign-out, credential snapshots, disconnect/scan
coordination, deferred exception callbacks, local-only pinned UPnP destinations,
stream size enforcement and resource cleanup.

These are regression checks, not full browser, packaged Agent, Supabase RLS or
end-to-end authentication tests. Database/RPC reconciliation is pending the live
`supabase/schema.sql` export. No SQL migration or Stripe integration is included.
MFA removal rechecks factors and AAL2 in the application; authoritative MFA/RLS
and direct Auth API behavior still require review in the actual Supabase project.
