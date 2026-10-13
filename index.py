import argparse
import base64
import ipaddress
import json
import plistlib
import re
import ssl
import sys
import uuid
from pathlib import Path


DOMAINS_PATH = Path(__file__).resolve().parent / "domains.json"

POLICY_NAME = "CACertificatesWithConstraints"
OUTPUT_NAMES = {
    "macos": "chrome-restricted-russian-ca.mobileconfig",
    "debian": "chrome-restricted-russian-ca.json",
    "windows": "chrome-restricted-russian-ca.reg",
}


def normalize_domains(values):
    if not isinstance(values, list) or any(not isinstance(value, str) for value in values):
        raise ValueError("domains.json должен содержать JSON-массив строк с DNS-именами.")
    if not values:
        raise ValueError("Укажите хотя бы один домен в domains.json.")
    result = []
    for value in values:
        value = value.strip().lower()
        subdomains_only = value.startswith(".")
        hostname = value[1:] if subdomains_only else value
        try:
            hostname = hostname.encode("idna").decode("ascii")
        except UnicodeError as error:
            raise ValueError(f"Некорректный домен: {value!r}") from error
        labels = hostname.split(".")
        if len(hostname) > 253 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label)
            for label in labels
        ):
            raise ValueError(f"Ожидается DNS-имя без URL, порта или wildcard: {value!r}")
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            raise ValueError(f"Укажите DNS-имя, а не IP-адрес: {value!r}")
        normalized = ("." if subdomains_only else "") + hostname
        if normalized not in result:
            result.append(normalized)
    return result


def read_domains(path):
    try:
        values = json.loads(path.read_text(encoding="utf-8-sig"))
    except FileNotFoundError as error:
        raise ValueError(f"Не найден файл доменов: {path}") from error
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValueError(f"Некорректный JSON в {path}: {error}") from error
    return normalize_domains(values)


def read_certificate(path):
    data = path.read_bytes()
    if b"-----BEGIN CERTIFICATE-----" in data:
        pem = data.decode("ascii").strip()
        if not re.fullmatch(
            r"-----BEGIN CERTIFICATE-----\s*([A-Za-z0-9+/=\s]+)\s*"
            r"-----END CERTIFICATE-----", pem
        ):
            raise ValueError("Файл должен содержать ровно один PEM-сертификат.")
        der = ssl.PEM_cert_to_DER_cert(pem)
    else:
        der = data
    # Проверка разбора X.509 в изолированном контексте, не установка в систему.
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=der)
    return der


def macos_profile(policy):
    return {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": "local.chrome.restricted-russian-ca",
        "PayloadUUID": str(uuid.uuid4()),
        "PayloadDisplayName": "Chrome: Russian CA — выбранные домены",
        "PayloadDescription": "Ограниченное доверие CA только внутри Chrome.",
        "PayloadScope": "User",
        "PayloadContent": [{
            "PayloadType": "com.apple.ManagedClient.preferences",
            "PayloadVersion": 1,
            "PayloadIdentifier": "local.chrome.restricted-russian-ca.preferences",
            "PayloadUUID": str(uuid.uuid4()),
            "PayloadDisplayName": "Ограниченное доверие CA в Chrome",
            "PayloadContent": {
                "com.google.Chrome": {
                    "Forced": [{"mcx_preference_settings": {POLICY_NAME: policy}}],
                },
            },
        }],
    }


def serialize_policy(target, policy):
    if target == "macos":
        return plistlib.dumps(macos_profile(policy))
    if target == "debian":
        return (json.dumps({POLICY_NAME: policy}, indent=2) + "\n").encode("utf-8")
    if target == "windows":
        # Сложные политики Chrome записываются одним REG_SZ с JSON, не подразделами.
        value = json.dumps(policy, separators=(",", ":"))
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        content = (
            "Windows Registry Editor Version 5.00\r\n\r\n"
            "[HKEY_CURRENT_USER\\Software\\Policies\\Google\\Chrome]\r\n"
            f'"{POLICY_NAME}"="{escaped}"\r\n'
        )
        return content.encode("utf-16")
    raise ValueError(f"Неизвестная платформа: {target}")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Создать политику ограниченного доверия CA для Google Chrome."
    )
    parser.add_argument("--platform", choices=["auto", *OUTPUT_NAMES], default="auto")
    parser.add_argument("--cert", type=Path, default=Path("russian_trusted_root_ca.cer"))
    parser.add_argument("--output", type=Path, help="Путь к выходному файлу.")
    args = parser.parse_args(argv)
    target = args.platform
    if target == "auto":
        target = {"darwin": "macos", "linux": "debian", "win32": "windows"}.get(sys.platform)
        if target is None:
            parser.error("Не удалось определить платформу; используйте --platform.")
    try:
        allowed_domains = read_domains(DOMAINS_PATH)
        der = read_certificate(args.cert)
        policy = [{
            "certificate": base64.b64encode(der).decode("ascii"),
            "constraints": {"permitted_dns_names": allowed_domains},
        }]
        output = args.output or Path(OUTPUT_NAMES[target])
        output.write_bytes(serialize_policy(target, policy))
    except (OSError, ValueError, UnicodeError) as error:
        parser.error(str(error))
    print(f"Создан: {output.resolve()}")
    print("Разрешённые домены:", ", ".join(allowed_domains))
    print("Настройки не установлены. Инструкции по установке: README.md")


if __name__ == "__main__":
    main()
