from __future__ import annotations

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
