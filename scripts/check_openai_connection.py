"""Explicit CLI smoke test: uv run python -m scripts.check_openai_connection."""

from src.ai_assistant import connectivity_smoke_test


def main() -> int:
    result = connectivity_smoke_test()
    print(f"{'SUCCESS' if result.success else 'ERROR'} [{result.code}]: {result.message}")
    return 0 if result.success else 1


if __name__ == "__main__":
    raise SystemExit(main())
