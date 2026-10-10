from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DOCS = {
    "en": ROOT / "README.md",
    "ru": ROOT / "docs" / "README.ru.md",
    "es": ROOT / "docs" / "README.es.md",
    "fr": ROOT / "docs" / "README.fr.md",
    "zh": ROOT / "docs" / "README.zh.md",
}
TUTORIAL_ROOT = (
    "https://github.com/alexar76/create-aimarket-agent/blob/main/docs/tutorials/"
)


def test_five_language_documentation_and_navigation_are_complete():
    tutorial_suffix = {
        "en": "themis.en.md",
        "ru": "themis.ru.md",
        "es": "themis.es.md",
        "fr": "themis.fr.md",
        "zh": "themis.zh.md",
    }
    for lang, path in DOCS.items():
        assert path.is_file(), lang
        text = path.read_text(encoding="utf-8")
        for token in (
            "AIMarket",
            "Metis",
            "Hub",
            "Alien Monitor",
            "agent.security.supply-chain.audit@v1",
            TUTORIAL_ROOT + tutorial_suffix[lang],
        ):
            assert token in text, (lang, token)
        assert tutorial_suffix[lang] in text, lang


def test_localized_documentation_uses_canonical_glossary_terms():
    required = {
        "ru": ("агент", "поставщик", "верификац", "квитанц"),
        "es": ("agente", "proveedor", "verificaci", "recibo"),
        "fr": ("agent", "fournisseur", "vérific", "reçu"),
        "zh": ("智能体", "提供方", "验证", "收据"),
    }
    for lang, terms in required.items():
        text = DOCS[lang].read_text(encoding="utf-8").casefold()
        assert all(term.casefold() in text for term in terms), lang


def test_security_documentation_matches_implemented_boundaries():
    security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
    env_example = (ROOT / ".env.example").read_text(encoding="utf-8")
    for token in (
        "256 KiB",
        "SSRF",
        "Ed25519",
        "rate limiting",
        "METIS_API_KEY",
    ):
        assert token in security
    for variable in (
        "METIS_MAX_JOBS",
        "METIS_MAX_CONCURRENT",
        "METIS_JOB_TTL_SECONDS",
        "METIS_TIMEOUT_SECONDS",
    ):
        assert variable in env_example


# ───────────────────────────── landing page i18n ─────────────────────────────

LANDING = ROOT / "docs" / "landing" / "index.html"
LANDING_LANGS = ("ru", "es", "fr", "zh")


def _landing() -> str:
    return LANDING.read_text(encoding="utf-8")


def _dictionary_keys(text: str, marker: str) -> set[str]:
    """Keys of one inline dictionary, delimited by its own balanced braces."""
    return set(re.findall(r"'([a-zA-Z0-9._]+)':", _dictionary_body(text, marker)))


def test_landing_declares_every_language_to_search_engines():
    text = _landing()
    for lang in ("en",) + LANDING_LANGS:
        assert f'hreflang="{lang}"' in text, lang
    assert 'hreflang="x-default"' in text


def test_every_landing_string_is_translated_into_every_language():
    """A key missing from one dictionary silently falls back to English."""
    text = _landing()
    required = set(re.findall(r'data-i18n="([a-zA-Z0-9._]+)"', text))
    required |= _dictionary_keys(text, "const JS_EN = ")
    assert len(required) > 100, "the landing lost its translation markers"
    for lang in LANDING_LANGS:
        marker = "const DICT = {" if lang == "ru" else f"DICT.{lang} = "
        translated = _dictionary_keys(text, marker)
        missing = sorted(required - translated)
        assert not missing, f"{lang} is missing {len(missing)} strings: {missing[:8]}"


def test_landing_switcher_and_engine_are_wired():
    text = _landing()
    for token in ('data-lang="en"', 'data-lang="zh"', "window.__i18n", "themis-lang"):
        assert token in text, token


def _dictionary_body(text: str, marker: str) -> str:
    start = text.index(marker)
    depth = 0
    for index in range(text.index("{", start), len(text)):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[start:index]
    raise AssertionError(f"unterminated dictionary for {marker}")


def test_landing_translations_use_canonical_glossary_terms():
    text = _landing()
    required = {
        "ru": ("допуск", "квитанц", "поставщик", "аттестац"),
        "es": ("admisión", "recibo", "proveedor", "atesta"),
        "fr": ("admission", "reçu", "fournisseur", "attest"),
        "zh": ("准入", "收据", "提供方", "证明"),
    }
    for lang, terms in required.items():
        marker = "const DICT = {" if lang == "ru" else f"DICT.{lang} = "
        body = _dictionary_body(text, marker).casefold()
        for term in terms:
            assert term.casefold() in body, (lang, term)


def test_landing_decision_tokens_stay_latin():
    """The glossary keeps approve / review / reject untranslated in UI chips."""
    text = _landing()
    for token in (">APPROVE<", ">REVIEW<", ">REJECT<"):
        assert token in text, token
