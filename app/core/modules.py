"""Official module register M01–M20 (KAR-PROJ-SA-RTM-006 v1.3).

Status values follow the project lifecycle:
  NOT_STARTED -> DESIGN_READY (STD-001) -> DEVELOPER_COMPLETE (STD-002) -> CLOSED (independent closure)
Developer completion is not independent closure (DEV-007).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class ModuleStatus(StrEnum):
    NOT_STARTED = "NOT_STARTED"
    DESIGN_READY = "DESIGN_READY"
    DEVELOPER_COMPLETE = "DEVELOPER_COMPLETE"
    CLOSED = "CLOSED"


@dataclass(frozen=True)
class Module:
    code: str
    name: str
    name_sw: str
    requirements: int
    status: ModuleStatus


MODULES: tuple[Module, ...] = (
    Module("M01", "Project Setup na Configuration", "Msingi wa mradi na mipangilio", 8, ModuleStatus.DEVELOPER_COMPLETE),
    Module("M02", "Database Schema na Migrations", "Muundo wa database", 13, ModuleStatus.DEVELOPER_COMPLETE),
    Module("M03", "Registration na Login", "Usajili na kuingia", 21, ModuleStatus.DEVELOPER_COMPLETE),
    Module("M04", "MFA, Sessions na Password Recovery", "Ulinzi wa ziada na sessions", 18, ModuleStatus.DEVELOPER_COMPLETE),
    Module("M05", "Users, Roles na Permissions", "Watumiaji na ruhusa", 32, ModuleStatus.DEVELOPER_COMPLETE),
    Module("M06", "Shared UI, Header na Navigation", "Muonekano wa pamoja", 11, ModuleStatus.DEVELOPER_COMPLETE),
    Module("M07", "Shops, Ownership na Staff", "Maduka na wamiliki", 21, ModuleStatus.DEVELOPER_COMPLETE),
    Module("M08", "Categories, Products na Images", "Bidhaa na picha", 16, ModuleStatus.NOT_STARTED),
    Module("M09", "Marketplace (Soko Kuu), Search na Filtering", "Soko kuu na utafutaji", 14, ModuleStatus.NOT_STARTED),
    Module("M10", "Shop Page na Shop Admin", "Ukurasa wa duka", 1, ModuleStatus.NOT_STARTED),
    Module("M11", "Cart, Checkout na Stock Reservation", "Kikapu na checkout", 5, ModuleStatus.NOT_STARTED),
    Module("M12", "Orders, Fulfillment na Delivery PIN", "Oda na usafirishaji", 20, ModuleStatus.NOT_STARTED),
    Module("M13", "Online Payments na Webhooks", "Malipo ya mtandaoni", 15, ModuleStatus.NOT_STARTED),
    Module("M14", "Cash on Delivery", "Kulipa mzigo ukifika", 11, ModuleStatus.NOT_STARTED),
    Module("M15", "Commission na Marketplace Contribution", "Kamisheni na michango", 31, ModuleStatus.NOT_STARTED),
    Module("M16", "Ledger, Settlements na Reconciliation", "Daftari la fedha", 13, ModuleStatus.NOT_STARTED),
    Module("M17", "Refunds, Donations na Changia", "Marejesho na Changia", 19, ModuleStatus.NOT_STARTED),
    Module("M18", "Reviews, Favorites na Addresses", "Maoni, vipendwa, anwani", 11, ModuleStatus.NOT_STARTED),
    Module("M19", "Analytics, Reports na Administration", "Takwimu na usimamizi", 23, ModuleStatus.NOT_STARTED),
    Module("M20", "Final Security Hardening, System Testing, Backup na Deployment", "Ukaguzi wa mwisho na kwenda live", 90, ModuleStatus.NOT_STARTED),
)

TOTAL_REQUIREMENTS = 393
