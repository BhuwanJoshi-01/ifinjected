"""Properties that must hold for any surrounding text."""

from __future__ import annotations

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from ifinjected.privacy import RedactionContext, Redactor

SECRET = "Zq8CanarySecretValue9xK"
GITHUB_TOKEN = "ghp_" + "Q7" * 18
CANARIES = (SECRET, GITHUB_TOKEN)
CASES = (
    f"API_KEY={SECRET}",
    f"DB_PASSWORD: '{SECRET}'",
    f'HF_TOKEN="{SECRET}"',
    f"postgres://bob:{SECRET}@db.internal:5432/app",
    f"Authorization: Bearer {SECRET}",
    f"env: SERVICE_TOKEN={SECRET}",
    f"push failed for {GITHUB_TOKEN}",
)
CONTEXT = RedactionContext(home="/home/alice", user="alice", hostname="alice-laptop")

# Printable text only: control characters are stripped before redaction and may
# legitimately change their neighbours (an escape sequence swallows the next letter).
printable = st.text(st.characters(blacklist_categories=("Cc", "Cs")), max_size=40)
shared_fixtures = settings(suppress_health_check=[HealthCheck.function_scoped_fixture])


@shared_fixtures
@given(prefix=printable, case=st.sampled_from(CASES), suffix=printable)
def test_secrets_never_survive_redaction(prefix: str, case: str, suffix: str) -> None:
    redacted = Redactor(CONTEXT).text(f"{prefix} {case} {suffix}")
    for canary in CANARIES:
        assert canary not in redacted


@shared_fixtures
@given(value=printable)
def test_redaction_is_idempotent_for_any_text(value: str) -> None:
    once = Redactor(CONTEXT).text(value)
    assert Redactor(CONTEXT).text(once) == once
