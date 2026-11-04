from .types import ScanReport, ScannerConfig, ShellVerdict, WarmupOptions, WolfExecutionOptions

__version__: str

class CancelledError(RuntimeError): ...
class ScannerBusyError(RuntimeError): ...

class ScanControl:
    def __init__(self, timeout_ms: int | None = None) -> None: ...
    def cancel(self) -> None: ...

class Scanner:
    def __init__(
        self, config: dict[str, object] | ScannerConfig | None = None, *,
        warmup: dict[str, object] | WarmupOptions | None = None, wolf_options: dict[str, int] | WolfExecutionOptions | None = None,
    ) -> None: ...
    def scan(
        self, text: str, *, pii: bool = True, dlp: bool = True,
        injection: bool = True, control: ScanControl | None = None,
    ) -> ScanReport: ...
    def shell_verdict(
        self, command: str, *, cwd: str | None = None, home: str | None = None,
        repo_root: str | None = None, dialect: str | None = None, with_facts: bool = False,
    ) -> ShellVerdict: ...
