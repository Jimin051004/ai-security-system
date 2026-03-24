from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from owasp import a01, a02, a03, a04, a05, a06, a07, a08, a09, a10
from owasp.types import Finding, ModuleScanResult, RequestContext, Severity

Scan = Callable[[RequestContext], Awaitable[ModuleScanResult]]


@dataclass(frozen=True, slots=True)
class OWASPModule:
    module_id: str
    owasp_id: str
    title: str
    scan: Scan


MODULES: tuple[OWASPModule, ...] = (
    OWASPModule(a01.MODULE_ID, a01.OWASP_ID, a01.TITLE, a01.scan),
    OWASPModule(a02.MODULE_ID, a02.OWASP_ID, a02.TITLE, a02.scan),
    OWASPModule(a03.MODULE_ID, a03.OWASP_ID, a03.TITLE, a03.scan),
    OWASPModule(a04.MODULE_ID, a04.OWASP_ID, a04.TITLE, a04.scan),
    OWASPModule(a05.MODULE_ID, a05.OWASP_ID, a05.TITLE, a05.scan),
    OWASPModule(a06.MODULE_ID, a06.OWASP_ID, a06.TITLE, a06.scan),
    OWASPModule(a07.MODULE_ID, a07.OWASP_ID, a07.TITLE, a07.scan),
    OWASPModule(a08.MODULE_ID, a08.OWASP_ID, a08.TITLE, a08.scan),
    OWASPModule(a09.MODULE_ID, a09.OWASP_ID, a09.TITLE, a09.scan),
    OWASPModule(a10.MODULE_ID, a10.OWASP_ID, a10.TITLE, a10.scan),
)

__all__ = [
    "MODULES",
    "OWASPModule",
    "Finding",
    "ModuleScanResult",
    "RequestContext",
    "Severity",
]
