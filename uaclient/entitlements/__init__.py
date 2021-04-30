from uaclient.entitlements.base import UAEntitlement  # noqa: F401
from uaclient.entitlements.cis import CISEntitlement
from uaclient.entitlements.cc import CommonCriteriaEntitlement
from uaclient.entitlements.esm import ESMAppsEntitlement, ESMInfraEntitlement
from uaclient.entitlements import fips
from uaclient.entitlements.livepatch import LivepatchEntitlement

from uaclient.config import UAConfig
from uaclient.util import is_config_value_true

try:
    from typing import cast, Dict, List, Type, Optional  # noqa: F401
except ImportError:
    # typing isn't available on trusty, so ignore its absence
    def cast(_, x):  # type: ignore
        return x


ENTITLEMENT_CLASSES = [
    CommonCriteriaEntitlement,
    CISEntitlement,
    ESMAppsEntitlement,
    ESMInfraEntitlement,
    fips.FIPSEntitlement,
    fips.FIPSUpdatesEntitlement,
    LivepatchEntitlement,
]  # type: List[Type[UAEntitlement]]


ENTITLEMENT_CLASS_BY_NAME = dict(
    (cast(str, cls.name), cls) for cls in ENTITLEMENT_CLASSES
)  # type: Dict[str, Type[UAEntitlement]]


def valid_services(allow_beta: bool = False) -> "List[str]":
    """Return a list of valid (non-beta) services.

    @param allow_beta: if we should allow beta services to be marked as valid
    """
    cfg = UAConfig()
    allow_beta_cfg = is_config_value_true(cfg.cfg, "features.allow_beta")
    allow_beta |= allow_beta_cfg

    if allow_beta:
        return sorted(ENTITLEMENT_CLASS_BY_NAME.keys())

    return sorted(
        [
            ent_name
            for ent_name, ent_cls in ENTITLEMENT_CLASS_BY_NAME.items()
            if not ent_cls.is_beta
        ]
    )
