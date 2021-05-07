from uaclient.entitlements import repo
from uaclient import util
from uaclient.config import update_ua_messages

try:
    from typing import Optional  # noqa: F401
except ImportError:
    # typing isn't available on trusty, so ignore its absence
    pass


class ESMBaseEntitlement(repo.RepoEntitlement):
    help_doc_url = "https://ubuntu.com/security/esm"

    def enable(self, *, silent_if_inapplicable: bool = False) -> bool:
        enable_performed = super().enable(
            silent_if_inapplicable=silent_if_inapplicable
        )
        if enable_performed:
            update_ua_messages(self.cfg)
        return enable_performed

    def disable(self, silent=False) -> bool:
        disable_performed = super().disable(silent=silent)
        if disable_performed:
            update_ua_messages(self.cfg)
        return disable_performed


class ESMAppsEntitlement(ESMBaseEntitlement):
    origin = "UbuntuESMApps"
    name = "esm-apps"
    title = "UA Apps: ESM"
    description = "UA Apps: Extended Security Maintenance (ESM)"
    repo_key_file = "ubuntu-advantage-esm-apps.gpg"
    is_beta = True

    @property
    def repo_pin_priority(self) -> "Optional[str]":
        """All LTS with the exception of Trusty should pin esm-apps."""
        series = util.get_platform_info()["series"]
        if series == "trusty":
            return None

        if self.valid_service:
            if util.is_lts(series):
                return "never"
        return None

    @property
    def disable_apt_auth_only(self) -> bool:
        """All LTSexcept Trusty remove APT auth files upon disable"""
        series = util.get_platform_info()["series"]
        if series == "trusty":
            return False

        if self.valid_service:
            return util.is_lts(series)
        return False


class ESMInfraEntitlement(ESMBaseEntitlement):
    name = "esm-infra"
    origin = "UbuntuESM"
    title = "UA Infra: ESM"
    description = "UA Infra: Extended Security Maintenance (ESM)"
    repo_key_file = "ubuntu-advantage-esm-infra-trusty.gpg"

    @property
    def repo_pin_priority(self) -> "Optional[str]":
        """Once a release goes into EOL it is entitled to ESM Infra."""
        if util.is_active_esm(util.get_platform_info()["series"]):
            return "never"
        return None  # No pinning on non-ESM releases

    @property
    def disable_apt_auth_only(self) -> bool:
        """Ubuntu EOL releases are in active ESM.

        Leave unauthenticated APT sources on disk with never pinning to ensure
        visibility to UA ESM: Infra packages for MOTD/APT messaging.
        """
        return util.is_active_esm(util.get_platform_info()["series"])
