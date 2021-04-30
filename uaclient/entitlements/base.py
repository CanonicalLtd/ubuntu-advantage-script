import os
import abc
from datetime import datetime
import logging
import re
import yaml

from uaclient.util import is_config_value_true

try:
    from typing import Any, Callable, Dict, List, Optional, Tuple  # noqa: F401

    StaticAffordance = Tuple[str, Callable[[], Any], bool]
except ImportError:
    # typing isn't available on trusty, so ignore its absence
    pass

from uaclient import config
from uaclient import contract
from uaclient import status
from uaclient import util
from uaclient.status import (
    ApplicabilityStatus,
    ContractStatus,
    UserFacingStatus,
    MESSAGE_INCOMPATIBLE_SERVICE_STOPS_ENABLE,
)
from uaclient.defaults import DEFAULT_HELP_FILE

RE_KERNEL_UNAME = (
    r"(?P<major>[\d]+)[.-](?P<minor>[\d]+)[.-](?P<patch>[\d]+\-[\d]+)"
    r"-(?P<flavor>[A-Za-z0-9_-]+)"
)


class UAEntitlement(metaclass=abc.ABCMeta):

    # Optional URL for top-level product service information
    help_doc_url = None  # type: str

    # Whether to assume yes to any messaging prompts
    assume_yes = False

    # Whether that entitlement is in beta stage
    is_beta = False

    # Help info message for the entitlement
    _help_info = None  # type: str

    # List of services that are incompatible with this service
    _incompatible_services = []  # type: "List[str]"

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """The lowercase name of this entitlement"""
        pass

    @property
    @abc.abstractmethod
    def title(self) -> str:
        """The human readable title of this entitlement"""
        pass

    @property
    @abc.abstractmethod
    def description(self) -> str:
        """A sentence describing this entitlement"""
        pass

    @property
    def help_info(self) -> str:
        """Help information for the entitlement"""
        if self._help_info is None:
            help_dict = {}

            if os.path.exists(DEFAULT_HELP_FILE):
                with open(DEFAULT_HELP_FILE, "r") as f:
                    help_dict = yaml.safe_load(f)

            self._help_info = help_dict.get(self.name, {}).get("help", "")

        return self._help_info

    # A tuple of 3-tuples with (failure_message, functor, expected_results)
    # If any static_affordance does not match expected_results fail with
    # <failure_message>. Overridden in livepatch and fips
    @property
    def static_affordances(self) -> "Tuple[StaticAffordance, ...]":
        return ()

    @property
    def incompatible_services(self) -> "List[str]":
        """
        Return a list of packages that aren't compatible with the entitlement.
        When we are enabling the entitlement we can directly ask the user
        if those entitlements can be disabled before proceding.
        Overridden in livepatch and fips
        """
        return self._incompatible_services

    def __init__(
        self,
        cfg: "Optional[config.UAConfig]" = None,
        assume_yes: bool = False,
        allow_beta: bool = False,
    ) -> None:
        """Setup UAEntitlement instance

        @param config: Parsed configuration dictionary
        """
        if not cfg:
            cfg = config.UAConfig()
        self.cfg = cfg
        self.assume_yes = assume_yes
        self.allow_beta = allow_beta
        self._valid_service = None

    @property
    def valid_service(self):
        """Check if the service is marked as valid (non-beta)"""
        if self._valid_service is None:
            self._valid_service = (
                not self.is_beta
                or self.allow_beta
                or is_config_value_true(self.cfg.cfg, "features.allow_beta")
            )

        return self._valid_service

    @abc.abstractmethod
    def enable(self, *, silent_if_inapplicable: bool = False) -> bool:
        """Enable specific entitlement.

        :param silent_if_inapplicable:
            Don't emit any messages until after it has been determined that
            this entitlement is applicable to the current machine.

        @return: True on success, False otherwise.
        """
        pass

    def can_disable(self, silent: bool = False) -> bool:
        """Report whether or not disabling is possible for the entitlement.

        @param silent: Boolean set True to silence printed messages/warnings.
        """
        application_status, _ = self.application_status()

        if application_status == status.ApplicationStatus.DISABLED:
            if not silent:
                print(
                    status.MESSAGE_ALREADY_DISABLED_TMPL.format(
                        title=self.title
                    )
                )
            return False
        return True

    def can_enable(
        self, silent: bool = False, enable_by_default: bool = False
    ) -> bool:
        """
        Report whether or not enabling is possible for the entitlement.

        :param enable_by_default: If True, do not stop enable if service
                                  is marked as beta
        :param silent: if True, suppress output
        """

        # If the contract needs to enable a beta service by default,
        # we will not stop it here
        if not self.valid_service and not enable_by_default:
            return False

        if self.is_access_expired():
            logging.debug(
                "Updating contract on service '%s' expiry", self.name
            )
            contract.request_updated_contract(self.cfg)
        if not self.contract_status() == ContractStatus.ENTITLED:
            if not silent:
                print(status.MESSAGE_UNENTITLED_TMPL.format(title=self.title))
            return False

        application_status, _ = self.application_status()
        if application_status != status.ApplicationStatus.DISABLED:
            if not silent:
                print(
                    status.MESSAGE_ALREADY_ENABLED_TMPL.format(
                        title=self.title
                    )
                )
            return False
        applicability_status, details = self.applicability_status()
        if applicability_status == status.ApplicabilityStatus.INAPPLICABLE:
            if not silent:
                print(details)
            return False

        if self.incompatible_services:
            return self.handle_incompatible_services()

        return True

    def handle_incompatible_services(self) -> bool:
        """
        Prompt user when incompatible services are found during enable.

        When enabling a service, we may find that there is an incompatible
        service already enable. In that situation, we can ask the user
        if the incompatible service should be disabled before proceeding.
        There are also different ways to configure that behavior:

        We can disable removing incompatible service during enable by
        adding the following lines into uaclient.conf:

        features:
          block_disable_on_enable: true

        We can also use the --allow-disable flag during enable to
        automatically disable any incompatible service during
        enable.
        """
        from uaclient.entitlements import ENTITLEMENT_CLASS_BY_NAME

        cfg_block_disable_on_enable = util.is_config_value_true(
            config=self.cfg.cfg,
            path_to_value="features.block_disable_on_enable",
        )
        for incompatible_service in self.incompatible_services:
            ent_cls = ENTITLEMENT_CLASS_BY_NAME.get(incompatible_service)

            if ent_cls:
                ent = ent_cls(self.cfg)
                enabled_status = status.ApplicationStatus.ENABLED

                is_service_enabled = (
                    ent.application_status()[0] == enabled_status
                )

                if is_service_enabled:
                    user_msg = status.MESSAGE_INCOMPATIBLE_SERVICE.format(
                        service_being_enabled=self.title,
                        incompatible_service=ent.title,
                    )

                    e_msg = MESSAGE_INCOMPATIBLE_SERVICE_STOPS_ENABLE.format(
                        service_being_enabled=self.title,
                        incompatible_service=ent.title,
                    )

                    if cfg_block_disable_on_enable:
                        logging.info(e_msg)
                        return False

                    if not util.prompt_for_confirmation(
                        msg=user_msg, assume_yes=self.assume_yes
                    ):
                        print(e_msg)
                        return False

                    disable_msg = "Disabling incompatible service: {}".format(
                        ent.title
                    )
                    logging.info(disable_msg)

                    ret = ent.disable()
                    if not ret:
                        return ret

        return True

    def applicability_status(self) -> "Tuple[ApplicabilityStatus, str]":
        """Check all contract affordances to vet current platform

        Affordances are a list of support constraints for the entitlement.
        Examples include a list of supported series, architectures for kernel
        revisions.

        :return:
            tuple of (ApplicabilityStatus, detailed_message). APPLICABLE if
            platform passes all defined affordances, INAPPLICABLE if it doesn't
            meet all of the provided constraints.
        """
        entitlement_cfg = self.cfg.entitlements.get(self.name)
        if not entitlement_cfg:
            return (
                ApplicabilityStatus.APPLICABLE,
                "no entitlement affordances checked",
            )
        for error_message, functor, expected_result in self.static_affordances:
            if functor() != expected_result:
                return ApplicabilityStatus.INAPPLICABLE, error_message
        affordances = entitlement_cfg["entitlement"].get("affordances", {})
        platform = util.get_platform_info()
        affordance_arches = affordances.get("architectures", [])
        if affordance_arches and platform["arch"] not in affordance_arches:
            return (
                ApplicabilityStatus.INAPPLICABLE,
                status.MESSAGE_INAPPLICABLE_ARCH_TMPL.format(
                    title=self.title,
                    arch=platform["arch"],
                    supported_arches=", ".join(affordance_arches),
                ),
            )
        affordance_series = affordances.get("series", [])
        if affordance_series and platform["series"] not in affordance_series:
            return (
                ApplicabilityStatus.INAPPLICABLE,
                status.MESSAGE_INAPPLICABLE_SERIES_TMPL.format(
                    title=self.title, series=platform["version"]
                ),
            )
        kernel = platform["kernel"]
        affordance_kernels = affordances.get("kernelFlavors", [])
        affordance_min_kernel = affordances.get("minKernelVersion")
        match = re.match(RE_KERNEL_UNAME, kernel)
        if affordance_kernels:
            if not match or match.group("flavor") not in affordance_kernels:
                return (
                    ApplicabilityStatus.INAPPLICABLE,
                    status.MESSAGE_INAPPLICABLE_KERNEL_TMPL.format(
                        title=self.title,
                        kernel=kernel,
                        supported_kernels=", ".join(affordance_kernels),
                    ),
                )
        if affordance_min_kernel:
            invalid_msg = status.MESSAGE_INAPPLICABLE_KERNEL_VER_TMPL.format(
                title=self.title,
                kernel=kernel,
                min_kernel=affordance_min_kernel,
            )
            try:
                kernel_major, kernel_minor = affordance_min_kernel.split(".")
                min_kern_major = int(kernel_major)
                min_kern_minor = int(kernel_minor)
            except ValueError:
                logging.warning(
                    "Could not parse minKernelVersion: %s",
                    affordance_min_kernel,
                )
                return (ApplicabilityStatus.INAPPLICABLE, invalid_msg)

            if not match:
                return ApplicabilityStatus.INAPPLICABLE, invalid_msg
            kernel_major = int(match.group("major"))
            kernel_minor = int(match.group("minor"))
            if kernel_major < min_kern_major:
                return ApplicabilityStatus.INAPPLICABLE, invalid_msg
            elif (
                kernel_major == min_kern_major
                and kernel_minor < min_kern_minor
            ):
                return ApplicabilityStatus.INAPPLICABLE, invalid_msg
        return ApplicabilityStatus.APPLICABLE, ""

    @abc.abstractmethod
    def disable(self, silent: bool = False) -> bool:
        """Disable specific entitlement

        @param silent: Boolean set True to silence print/log of messages

        @return: True on success, False otherwise.
        """
        pass

    def contract_status(self) -> ContractStatus:
        """Return whether the user is entitled to the entitlement or not"""
        if not self.cfg.is_attached:
            return ContractStatus.UNENTITLED
        entitlement_cfg = self.cfg.entitlements.get(self.name, {})
        if entitlement_cfg and entitlement_cfg["entitlement"].get("entitled"):
            return ContractStatus.ENTITLED
        return ContractStatus.UNENTITLED

    def is_access_expired(self) -> bool:
        """Return entitlement access info as stale and needing refresh."""
        entitlement_contract = self.cfg.entitlements.get(self.name, {})
        # TODO(No expiry per resource in MVP yet)
        expire_str = entitlement_contract.get("expires")
        if not expire_str:
            return False
        expiry = datetime.strptime(expire_str, "%Y-%m-%dT%H:%M:%S.%fZ")
        if expiry >= datetime.utcnow():
            return False
        return True

    def _check_application_status_on_cache(self) -> "status.ApplicationStatus":
        """Check on the state of application on the status cache."""
        status_cache = self.cfg.read_cache("status-cache")

        if status_cache is None:
            return status.ApplicationStatus.DISABLED

        services_status_list = status_cache.get("services", [])

        for service in services_status_list:
            if service.get("name") == self.name:
                service_status = service.get("status")

                if service_status == "enabled":
                    return status.ApplicationStatus.ENABLED
                else:
                    return status.ApplicationStatus.DISABLED

        return status.ApplicationStatus.DISABLED

    def process_contract_deltas(
        self,
        orig_access: "Dict[str, Any]",
        deltas: "Dict[str, Any]",
        allow_enable: bool = False,
    ) -> bool:
        """Process any contract access deltas for this entitlement.

        :param orig_access: Dictionary containing the original
            resourceEntitlement access details.
        :param deltas: Dictionary which contains only the changed access keys
        and values.
        :param allow_enable: Boolean set True if allowed to perform the enable
            operation. When False, a message will be logged to inform the user
            about the recommended enabled service.

        :return: True when delta operations are processed; False when noop.
        :raise: UserFacingError when auto-enable fails unexpectedly.
        """
        if not deltas:
            return True  # We processed all deltas that needed processing

        delta_entitlement = deltas.get("entitlement", {})
        delta_directives = delta_entitlement.get("directives", {})
        status_cache = self.cfg.read_cache("status-cache")

        transition_to_unentitled = bool(delta_entitlement == util.DROPPED_KEY)
        if not transition_to_unentitled:
            if delta_entitlement:
                util.apply_series_overrides(deltas)
                delta_entitlement = deltas["entitlement"]
            if orig_access and "entitled" in delta_entitlement:
                transition_to_unentitled = delta_entitlement["entitled"] in (
                    False,
                    util.DROPPED_KEY,
                )
        if transition_to_unentitled:
            if delta_directives and status_cache:
                application_status = self._check_application_status_on_cache()
            else:
                application_status, _ = self.application_status()

            if application_status != status.ApplicationStatus.DISABLED:
                if self.can_disable(silent=True):
                    self.disable()
                    logging.info(
                        "Due to contract refresh, '%s' is now disabled.",
                        self.name,
                    )
                else:
                    logging.warning(
                        "Unable to disable '%s' as recommended during contract"
                        " refresh. Service is still active. See"
                        " `ua status`",
                        self.name,
                    )
            # Clean up former entitled machine-access-<name> response cache
            # file because uaclient doesn't access machine-access-* routes or
            # responses on unentitled services.
            self.cfg.delete_cache_key("machine-access-{}".format(self.name))
            return True

        resourceToken = orig_access.get("resourceToken")
        if not resourceToken:
            resourceToken = deltas.get("resourceToken")
        delta_obligations = delta_entitlement.get("obligations", {})
        enable_by_default = bool(
            delta_obligations.get("enableByDefault") and resourceToken
        )

        if enable_by_default:
            self.allow_beta = True

        can_enable = self.can_enable(silent=True)
        if can_enable and enable_by_default:
            if allow_enable:
                msg = status.MESSAGE_ENABLE_BY_DEFAULT_TMPL.format(
                    name=self.name
                )
                logging.info(msg)
                self.enable()
            else:
                msg = status.MESSAGE_ENABLE_BY_DEFAULT_MANUAL_TMPL.format(
                    name=self.name
                )
                logging.info(msg)
            return True

        return False

    def user_facing_status(self) -> "Tuple[UserFacingStatus, str]":
        """Return (user-facing status, details) for entitlement"""
        applicability, details = self.applicability_status()
        if applicability != ApplicabilityStatus.APPLICABLE:
            return UserFacingStatus.INAPPLICABLE, details
        entitlement_cfg = self.cfg.entitlements.get(self.name)
        if not entitlement_cfg:
            return (
                UserFacingStatus.UNAVAILABLE,
                "{} is not entitled".format(self.title),
            )
        elif entitlement_cfg["entitlement"].get("entitled", False) is False:
            return (
                UserFacingStatus.UNAVAILABLE,
                "{} is not entitled".format(self.title),
            )

        application_status, explanation = self.application_status()
        user_facing_status = {
            status.ApplicationStatus.ENABLED: UserFacingStatus.ACTIVE,
            status.ApplicationStatus.DISABLED: UserFacingStatus.INACTIVE,
        }[application_status]
        return user_facing_status, explanation

    @abc.abstractmethod
    def application_status(self) -> "Tuple[status.ApplicationStatus, str]":
        """
        The current status of application of this entitlement

        :return:
            A tuple of (ApplicationStatus, human-friendly reason)
        """
        pass
