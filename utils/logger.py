from datetime import datetime


def log(module: str, message: str) -> None:
    timestamp = datetime.now().strftime("%H:%M:%S")
    print(f"[{timestamp}] [{module}] {message}")


def log_section(title: str) -> None:
    line = "═" * 42
    print(f"\n{line}")
    print(f"  {title}")
    print(f"{line}")


def log_ok(module: str, message: str) -> None:
    log(module, f"✓ {message}")


def log_error(module: str, message: str) -> None:
    log(module, f"✗ ERROR — {message}")


def log_warning(module: str, message: str) -> None:
    log(module, f"⚠ {message}")
