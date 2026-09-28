import pytest
from app.masking.secret_masker import SecretMasker

masker = SecretMasker()


def test_masks_api_key():
    text = "api_key=sk-1234567890abcdef"
    result = masker.mask(text)
    assert "sk-1234567890abcdef" not in result
    assert "*****" in result


def test_masks_password():
    text = "password=super_secret_123!"
    result = masker.mask(text)
    assert "super_secret_123!" not in result
    assert "*****" in result


def test_masks_token():
    text = "token=eyJhbGciOiJIUzI1NiJ9.abc"
    result = masker.mask(text)
    assert "eyJhbGciOiJIUzI1NiJ9.abc" not in result


def test_preserves_non_sensitive_text():
    text = "This is a normal log message with no secrets."
    result = masker.mask(text)
    assert result == text


def test_masks_secret_key():
    text = 'SECRET_KEY = "my-django-secret-key"'
    result = masker.mask(text)
    assert "my-django-secret-key" not in result


def test_case_insensitive_masking():
    text = "PASSWORD=abc123"
    result = masker.mask(text)
    assert "abc123" not in result
