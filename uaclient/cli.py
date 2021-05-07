#!/usr/bin/env python

"""Client to manage Ubuntu Advantage services on a machine."""

import argparse
from functools import wraps
import json
import logging
import os
import pathlib
import re
import sys
import textwrap
import time

try:
    from typing import List  # noqa
except ImportError:
    # typing isn't available on trusty, so ignore its absence
    pass


from uaclient import config
from uaclient import contract
from uaclient import entitlements
from uaclient import exceptions
from uaclient import security
from uaclient import status as ua_status
from uaclient import util
from uaclient import version
from uaclient.clouds import identity

NAME = "ua"

USAGE_TMPL = "{name} {command} [flags]"
EPILOG_TMPL = (
    "Use {name} {command} --help for more information about a command."
)

STATUS_HEADER_TMPL = """\
Account: {account}
Subscription: {subscription}
Valid until: {contract_expiry}
Technical support level: {tech_support_level}
"""
UA_AUTH_TOKEN_URL = "https://auth.contracts.canonical.com"

DEFAULT_LOG_FORMAT = (
    "%(asctime)s - %(filename)s:(%(lineno)d) [%(levelname)s]: %(message)s"
)

STATUS_FORMATS = ["tabular", "json"]


# Set a module-level callable here so we don't have to reinstantiate
# UAConfig in order to determine dynamic data_path exception handling of
# main_error_handler
_CLEAR_LOCK_FILE = None


class UAArgumentParser(argparse.ArgumentParser):
    def __init__(
        self,
        prog=None,
        usage=None,
        epilog=None,
        formatter_class=argparse.HelpFormatter,
        base_desc: str = None,
        non_beta_services_desc: "List[str]" = None,
        beta_services_desc: "List[str]" = None,
    ):
        super().__init__(
            prog=prog,
            usage=usage,
            epilog=epilog,
            formatter_class=formatter_class,
        )

        self.base_desc = base_desc
        self.non_beta_services_desc = non_beta_services_desc
        self.beta_services_desc = beta_services_desc

    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(2, message + "\n")

    def print_help(self, file=None, show_all=False):
        desc_vars = [
            self.base_desc,
            self.non_beta_services_desc,
            self.beta_services_desc,
        ]
        if any(desc_vars):
            services = sorted(self.non_beta_services_desc)
            if show_all:
                services = sorted(services + self.beta_services_desc)
            self.description = "\n".join([self.base_desc] + services)
        super().print_help(file=file)


def assert_lock_file(lock_holder=None):
    """Decorator asserting exclusive access to lock file

    Create a lock file if absent. The lock file will contain a pid of the
        running process, and a customer-visible description of the lock holder.

    :param lock_holder: String with the service name or command which is
        holding the lock.

        This lock_holder string will be customer visible in status.json.

    :raises: LockHeldError if lock is held.
    """

    def wrapper(f):
        @wraps(f)
        def new_f(args, cfg, **kwargs):
            global _CLEAR_LOCK_FILE
            (lock_pid, cur_lock_holder) = cfg.check_lock_info()
            if lock_pid > 0:
                raise exceptions.LockHeldError(
                    lock_request=lock_holder,
                    lock_holder=cur_lock_holder,
                    pid=lock_pid,
                )
            cfg.write_cache("lock", "{}:{}".format(os.getpid(), lock_holder))
            notice_msg = "Operation in progress: {}".format(lock_holder)
            cfg.add_notice("", notice_msg)
            _CLEAR_LOCK_FILE = cfg.delete_cache_key
            retval = f(args, cfg, **kwargs)
            cfg.delete_cache_key("lock")
            _CLEAR_LOCK_FILE = None  # Unset due to successful lock delete
            return retval

        return new_f

    return wrapper


def assert_root(f):
    """Decorator asserting root user"""

    @wraps(f)
    def new_f(*args, **kwargs):
        if os.getuid() != 0:
            raise exceptions.NonRootUserError()
        return f(*args, **kwargs)

    return new_f


def assert_attached(unattached_msg_tmpl=None):
    """Decorator asserting attached config.

    :param unattached_msg_tmpl: Optional msg template to format if raising an
        UnattachedError
    """

    def wrapper(f):
        @wraps(f)
        def new_f(args, cfg, **kwargs):
            if not cfg.is_attached:
                if unattached_msg_tmpl:
                    names = getattr(args, "service", "None")
                    msg = unattached_msg_tmpl.format(name=", ".join(names))
                    exception = exceptions.UnattachedError(msg)
                else:
                    exception = exceptions.UnattachedError()
                raise exception
            return f(args, cfg, **kwargs)

        return new_f

    return wrapper


def assert_not_attached(f):
    """Decorator asserting unattached config."""

    @wraps(f)
    def new_f(args, cfg):
        if cfg.is_attached:
            raise exceptions.AlreadyAttachedError(cfg)
        return f(args, cfg)

    return new_f


def auto_attach_parser(parser):
    """Build or extend an arg parser for auto-attach subcommand."""
    parser.prog = "auto-attach"
    parser.description = (
        "Automatically attach an Ubuntu Advantage token on Ubuntu Pro"
        " images."
    )
    parser.usage = USAGE_TMPL.format(name=NAME, command=parser.prog)
    parser._optionals.title = "Flags"
    return parser


def attach_parser(parser):
    """Build or extend an arg parser for attach subcommand."""
    parser.usage = USAGE_TMPL.format(name=NAME, command="attach <token>")
    parser.prog = "attach"
    parser.description = (
        "Attach this machine to Ubuntu Advantage with a token obtained"
        " from https://ubuntu.com/advantage"
    )
    parser._optionals.title = "Flags"
    parser.add_argument(
        "token",
        nargs="?",  # action_attach asserts this required argument
        help="token obtained for Ubuntu Advantage authentication: {}".format(
            UA_AUTH_TOKEN_URL
        ),
    )
    parser.add_argument(
        "--no-auto-enable",
        action="store_false",
        dest="auto_enable",
        help="do not enable any recommended services automatically",
    )
    return parser


def fix_parser(parser):
    """Build or extend an arg parser for fix subcommand."""
    parser.usage = USAGE_TMPL.format(
        name=NAME, command="fix <CVE-yyyy-nnnn+>|<USN-nnnn-d+>"
    )
    parser.prog = "fix"
    parser.description = (
        "Inspect and resolve CVEs and USNs (Ubuntu Security Notices) on this"
        " machine."
    )
    parser._optionals.title = "Flags"
    parser.add_argument(
        "security_issue",
        help=(
            "Security vulnerability ID to inspect and resolve on this system."
            " Format: CVE-yyyy-nnnn, CVE-yyyy-nnnnnnn or USN-nnnn-dd"
        ),
    )
    return parser


def refresh_parser(parser):
    """Build or extend an arg parser for refresh subcommand."""
    parser.prog = "refresh"
    parser.description = (
        "Refresh existing Ubuntu Advantage contract and update services."
    )
    parser.usage = USAGE_TMPL.format(name=NAME, command=parser.prog)
    parser._optionals.title = "Flags"
    return parser


def action_fix(args, cfg, **kwargs):
    if not re.match(security.CVE_OR_USN_REGEX, args.security_issue):
        msg = (
            'Error: issue "{}" is not recognized.\n'
            'Usage: "ua fix CVE-yyyy-nnnn" or "ua fix USN-nnnn"'
        ).format(args.security_issue)
        raise exceptions.UserFacingError(msg)

    security.fix_security_issue_id(cfg, args.security_issue)
    return 0


def detach_parser(parser):
    """Build or extend an arg parser for detach subcommand."""
    usage = USAGE_TMPL.format(name=NAME, command="detach")
    parser.usage = usage
    parser.prog = "detach"
    parser.description = "Detach this machine from Ubuntu Advantage services."
    parser._optionals.title = "Flags"
    parser.add_argument(
        "--assume-yes",
        action="store_true",
        help="do not prompt for confirmation before performing the detach",
    )
    return parser


def help_parser(parser):
    """Build or extend an arg parser for help subcommand."""
    usage = USAGE_TMPL.format(name=NAME, command="help [service]")
    parser.usage = usage
    parser.prog = "help"
    parser.description = (
        "Provide detailed information about Ubuntu Advantage services."
    )
    parser._positionals.title = "Arguments"
    parser.add_argument(
        "service",
        action="store",
        nargs="?",
        help="a service to view help output for. One of: {}".format(
            ", ".join(entitlements.valid_services())
        ),
    )

    parser.add_argument(
        "--format",
        action="store",
        choices=STATUS_FORMATS,
        default=STATUS_FORMATS[0],
        help=(
            "output help in the specified format (default: {})".format(
                STATUS_FORMATS[0]
            )
        ),
    )

    parser.add_argument(
        "--all",
        action="store_true",
        help="Allow the visualization of beta services",
    )

    return parser


def enable_parser(parser):
    """Build or extend an arg parser for enable subcommand."""
    usage = USAGE_TMPL.format(
        name=NAME, command="enable <service> [<service>]"
    )
    parser.description = "Enable an Ubuntu Advantage service."
    parser.usage = usage
    parser.prog = "enable"
    parser._positionals.title = "Arguments"
    parser._optionals.title = "Flags"
    parser.add_argument(
        "service",
        action="store",
        nargs="+",
        help=(
            "the name(s) of the Ubuntu Advantage services to enable."
            " One of: {}".format(", ".join(entitlements.valid_services()))
        ),
    )
    parser.add_argument(
        "--assume-yes",
        action="store_true",
        help="do not prompt for confirmation before performing the enable",
    )
    parser.add_argument(
        "--beta", action="store_true", help="allow beta service to be enabled"
    )
    return parser


def disable_parser(parser):
    """Build or extend an arg parser for disable subcommand."""
    usage = USAGE_TMPL.format(
        name=NAME, command="disable <service> [<service>]"
    )
    parser.description = "Disable an Ubuntu Advantage service."
    parser.usage = usage
    parser.prog = "disable"
    parser._positionals.title = "Arguments"
    parser._optionals.title = "Flags"
    parser.add_argument(
        "service",
        action="store",
        nargs="+",
        help=(
            "the name(s) of the Ubuntu Advantage services to disable"
            " One of: {}".format(", ".join(entitlements.valid_services()))
        ),
    )
    parser.add_argument(
        "--assume-yes",
        action="store_true",
        help="do not prompt for confirmation before performing the disable",
    )
    return parser


def status_parser(parser):
    """Build or extend an arg parser for status subcommand."""
    usage = USAGE_TMPL.format(name=NAME, command="status")
    parser.usage = usage
    parser.description = (
        "Output the status information for Ubuntu Advantage services."
    )
    parser.prog = "status"
    # This formatter_class ensures that our formatting below isn't lost
    parser.formatter_class = argparse.RawDescriptionHelpFormatter
    parser.description = textwrap.dedent(
        """\
        Report current status of Ubuntu Advantage services on system.

        This shows whether this machine is attached to an Ubuntu Advantage
        support contract. When attached, the report includes the specific
        support contract details including contract name, expiry dates, and the
        status of each service on this system.

        The attached status output has four columns:

        * SERVICE: name of the service
        * ENTITLED: whether the contract to which this machine is attached
          entitles use of this service. Possible values are: yes or no
        * STATUS: whether the service is enabled on this machine. Possible
          values are: enabled, disabled, n/a (if your contract entitles
          you to the service, but it isn't available for this machine) or — (if
          you aren't entitled to this service)
        * DESCRIPTION: a brief description of the service

        The unattached status output instead has three columns. SERVICE
        and DESCRIPTION are the same as above, and there is the addition
        of:

        * AVAILABLE: whether this service would be available if this machine
          were attached. The possible values are yes or no.
        """
    )

    parser.add_argument(
        "--wait",
        action="store_true",
        default=False,
        help="Block waiting on ua to complete",
    )
    parser.add_argument(
        "--format",
        action="store",
        choices=STATUS_FORMATS,
        default=STATUS_FORMATS[0],
        help=(
            "output status in the specified format (default: {})".format(
                STATUS_FORMATS[0]
            )
        ),
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Allow the visualization of beta services",
    )
    parser._optionals.title = "Flags"
    return parser


def _perform_disable(entitlement_name, cfg, *, assume_yes):
    """Perform the disable action on a named entitlement.

    :param entitlement_name: the name of the entitlement to enable
    :param cfg: the UAConfig to pass to the entitlement
    :param assume_yes:
        Assume a yes response for any prompts during service enable

    @return: True on success, False otherwise
    """
    ent_cls = entitlements.ENTITLEMENT_CLASS_BY_NAME[entitlement_name]
    entitlement = ent_cls(cfg, assume_yes=assume_yes)
    ret = entitlement.disable()
    cfg.status()  # Update the status cache
    return ret


def get_valid_entitlement_names(names: "List[str]"):
    """Return a list of valid entitlement names.

    :param names: List of entitlements to validate
    :return: a tuple of List containing the valid and invalid entitlements
    """
    entitlements_found = []

    for ent_name in names:
        if ent_name in entitlements.ENTITLEMENT_CLASS_BY_NAME:
            entitlements_found.append(ent_name)

    entitlements_not_found = sorted(set(names) - set(entitlements_found))

    return entitlements_found, entitlements_not_found


@assert_root
@assert_attached(ua_status.MESSAGE_ENABLE_FAILURE_UNATTACHED_TMPL)
@assert_lock_file("ua disable")
def action_disable(args, cfg, **kwargs):
    """Perform the disable action on a list of entitlements.

    @return: 0 on success, 1 otherwise
    """
    names = getattr(args, "service", [])
    entitlements_found, entitlements_not_found = get_valid_entitlement_names(
        names
    )
    tmpl = ua_status.MESSAGE_INVALID_SERVICE_OP_FAILURE_TMPL
    ret = True

    for entitlement in entitlements_found:
        ret &= _perform_disable(entitlement, cfg, assume_yes=args.assume_yes)

    if entitlements_not_found:
        valid_names = (
            "Try "
            + ", ".join(entitlements.valid_services(allow_beta=True))
            + "."
        )
        service_msg = "\n".join(
            textwrap.wrap(valid_names, width=80, break_long_words=False)
        )
        raise exceptions.UserFacingError(
            tmpl.format(
                operation="disable",
                name=", ".join(entitlements_not_found),
                service_msg=service_msg,
            )
        )

    return 0 if ret else 1


def _perform_enable(
    entitlement_name: str,
    cfg: config.UAConfig,
    *,
    assume_yes: bool = False,
    silent_if_inapplicable: bool = False,
    allow_beta: bool = False
) -> bool:
    """Perform the enable action on a named entitlement.

    (This helper excludes any messaging, so that different enablement code
    paths can message themselves.)

    :param entitlement_name: the name of the entitlement to enable
    :param cfg: the UAConfig to pass to the entitlement
    :param assume_yes:
        Assume a yes response for any prompts during service enable
    :param silent_if_inapplicable:
        don't output messages when determining if an entitlement can be
        enabled on this system
    :param allow_beta: Allow enabling beta services

    @return: True on success, False otherwise
    """
    ent_cls = entitlements.ENTITLEMENT_CLASS_BY_NAME[entitlement_name]
    entitlement = ent_cls(cfg, assume_yes=assume_yes, allow_beta=allow_beta)
    ret = entitlement.enable(silent_if_inapplicable=silent_if_inapplicable)
    cfg.status()  # Update the status cache
    return ret


@assert_root
@assert_attached(ua_status.MESSAGE_ENABLE_FAILURE_UNATTACHED_TMPL)
@assert_lock_file("ua enable")
def action_enable(args, cfg, **kwargs):
    """Perform the enable action on a named entitlement.

    @return: 0 on success, 1 otherwise
    """
    print(ua_status.MESSAGE_REFRESH_ENABLE)
    try:
        contract.request_updated_contract(cfg)
    except (util.UrlError, exceptions.UserFacingError):
        # Inability to refresh is not a critical issue during enable
        logging.debug(ua_status.MESSAGE_REFRESH_FAILURE, exc_info=True)

    names = getattr(args, "service", [])
    entitlements_found, entitlements_not_found = get_valid_entitlement_names(
        names
    )
    valid_services_names = entitlements.valid_services(allow_beta=args.beta)
    ret = True

    for entitlement in entitlements_found:
        try:
            ent_ret = _perform_enable(
                entitlement,
                cfg,
                assume_yes=args.assume_yes,
                allow_beta=args.beta,
            )

            if not ent_ret and entitlement not in valid_services_names:
                entitlements_not_found.append(entitlement)

            ret &= ent_ret
        except exceptions.UserFacingError as e:
            print(e)

    if entitlements_not_found:
        valid_names = ", ".join(valid_services_names)
        service_msg = "\n".join(
            textwrap.wrap(
                "Try " + valid_names + ".", width=80, break_long_words=False
            )
        )
        tmpl = ua_status.MESSAGE_INVALID_SERVICE_OP_FAILURE_TMPL
        raise exceptions.UserFacingError(
            tmpl.format(
                operation="enable",
                name=", ".join(entitlements_not_found),
                service_msg=service_msg,
            )
        )

    return 0 if ret else 1


@assert_root
@assert_attached()
@assert_lock_file("ua detach")
def action_detach(args, cfg) -> int:
    """Perform the detach action for this machine.

    @return: 0 on success, 1 otherwise
    """
    return _detach(cfg, assume_yes=args.assume_yes)


def _detach(cfg: config.UAConfig, assume_yes: bool) -> int:
    """Detach the machine from the active Ubuntu Advantage subscription,

    :param cfg: a ``config.UAConfig`` instance
    :param assume_yes: Assume a yes answer to any prompts requested.
         In this case, it means automatically disable any service during
         detach.

    @return: 0 on success, 1 otherwise
    """
    to_disable = []
    for ent_cls in entitlements.ENTITLEMENT_CLASSES:
        ent = ent_cls(cfg=cfg, assume_yes=assume_yes)
        if ent.can_disable(silent=True):
            to_disable.append(ent)
    if to_disable:
        suffix = "s" if len(to_disable) > 1 else ""
        print("Detach will disable the following service{}:".format(suffix))
        for ent in to_disable:
            print("    {}".format(ent.name))
    if not util.prompt_for_confirmation(assume_yes=assume_yes):
        return 1
    for ent in to_disable:
        ent.disable(silent=True)
    contract_client = contract.UAContractClient(cfg)
    machine_token = cfg.machine_token["machineToken"]
    contract_id = cfg.machine_token["machineTokenInfo"]["contractInfo"]["id"]
    contract_client.detach_machine_from_contract(machine_token, contract_id)
    cfg.delete_cache()
    config.update_ua_messages(cfg)
    print(ua_status.MESSAGE_DETACH_SUCCESS)
    return 0


def _attach_with_token(
    cfg: config.UAConfig, token: str, allow_enable: bool
) -> int:
    """Common functionality to take a token and attach via contract backend"""
    try:
        contract.request_updated_contract(
            cfg, token, allow_enable=allow_enable
        )
    except util.UrlError as exc:
        with util.disable_log_to_console():
            logging.exception(exc)
        print(ua_status.MESSAGE_ATTACH_FAILURE)
        cfg.status()  # Persist updated status in the event of partial attach
        config.update_ua_messages(cfg)
        return 1
    except exceptions.UserFacingError as exc:
        logging.warning(exc.msg)
        cfg.status()  # Persist updated status in the event of partial attach
        config.update_ua_messages(cfg)
        return 1

    contract_name = cfg.machine_token["machineTokenInfo"]["contractInfo"][
        "name"
    ]

    if contract_name:
        print(
            ua_status.MESSAGE_ATTACH_SUCCESS_TMPL.format(
                contract_name=contract_name
            )
        )
    else:
        print(ua_status.MESSAGE_ATTACH_SUCCESS_NO_CONTRACT_NAME)

    config.update_ua_messages(cfg)
    action_status(args=None, cfg=cfg)
    return 0


def _get_contract_token_from_cloud_identity(cfg: config.UAConfig) -> str:
    """Detect cloud_type and request a contract token from identity info.

    :param cfg: a ``config.UAConfig`` instance

    :raise NonAutoAttachImageError: When not on an auto-attach image type.
    :raise UrlError: On unexpected connectivity issues to contract
        server or inability to access identity doc from metadata service.
    :raise ContractAPIError: On unexpected errors when talking to the contract
        server.
    :raise NonAutoAttachImageError: If this cloud type does not have
        auto-attach support.

    :return: contract token obtained from identity doc
    """
    try:
        instance = identity.cloud_instance_factory()
    except exceptions.UserFacingError as e:
        if cfg.is_attached:
            # We are attached on non-Pro Image, just report already attached
            raise exceptions.AlreadyAttachedError(cfg)
        # Unattached on non-Pro return UserFacing error msg details
        raise e
    current_iid = identity.get_instance_id()
    if cfg.is_attached:
        prev_iid = cfg.read_cache("instance-id")
        if str(current_iid) == str(prev_iid):
            raise exceptions.AlreadyAttachedError(cfg)
        print("Re-attaching Ubuntu Advantage subscription on new instance")
        if _detach(cfg, assume_yes=True) != 0:
            raise exceptions.UserFacingError(
                ua_status.MESSAGE_DETACH_AUTOMATION_FAILURE
            )
    contract_client = contract.UAContractClient(cfg)
    try:
        tokenResponse = contract_client.request_auto_attach_contract_token(
            instance=instance
        )
    except contract.ContractAPIError as e:
        if e.code and 400 <= e.code < 500:
            raise exceptions.NonAutoAttachImageError(
                ua_status.MESSAGE_UNSUPPORTED_AUTO_ATTACH
            )
        raise e
    if current_iid:
        cfg.write_cache("instance-id", current_iid)

    return tokenResponse["contractToken"]


@assert_root
@assert_lock_file("ua auto-attach")
def action_auto_attach(args, cfg):
    disable_auto_attach = util.is_config_value_true(
        config=cfg.cfg, path_to_value="features.disable_auto_attach"
    )
    if disable_auto_attach:
        msg = "Skipping auto-attach. Config disable_auto_attach is set."
        logging.debug(msg)
        print(msg)
        return 0
    token = _get_contract_token_from_cloud_identity(cfg)
    return _attach_with_token(cfg, token=token, allow_enable=True)


@assert_not_attached
@assert_root
@assert_lock_file("ua attach")
def action_attach(args, cfg):
    if not args.token:
        raise exceptions.UserFacingError(
            ua_status.MESSAGE_ATTACH_REQUIRES_TOKEN
        )
    return _attach_with_token(
        cfg, token=args.token, allow_enable=args.auto_enable
    )


def get_parser():
    service_line_tmpl = " - {name}: {description}{url}"
    base_desc = __doc__
    non_beta_services_desc = []
    beta_services_desc = []
    sorted_classes = sorted(entitlements.ENTITLEMENT_CLASS_BY_NAME.items())
    for name, ent_cls in sorted_classes:
        if ent_cls.help_doc_url:
            url = " ({})".format(ent_cls.help_doc_url)
        else:
            url = ""
        service_line = service_line_tmpl.format(
            name=name, description=ent_cls.description, url=url
        )
        if len(service_line) <= 80:
            service_info = [service_line]
        else:
            wrapped_words = []
            line = service_line
            while len(line) > 80:
                [line, wrapped_word] = line.rsplit(" ", 1)
                wrapped_words.insert(0, wrapped_word)
            service_info = [line + "\n   " + " ".join(wrapped_words)]

        if ent_cls.is_beta:
            beta_services_desc.extend(service_info)
        else:
            non_beta_services_desc.extend(service_info)

    parser = UAArgumentParser(
        prog=NAME,
        formatter_class=argparse.RawDescriptionHelpFormatter,
        usage=USAGE_TMPL.format(name=NAME, command="[command]"),
        epilog=EPILOG_TMPL.format(name=NAME, command="[command]"),
        base_desc=base_desc,
        non_beta_services_desc=non_beta_services_desc,
        beta_services_desc=beta_services_desc,
    )
    parser.add_argument(
        "--debug",
        action="store_true",
        help="show all debug log messages to console",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=get_version(),
        help="show version of {}".format(NAME),
    )
    parser._optionals.title = "Flags"
    subparsers = parser.add_subparsers(
        title="Available Commands", dest="command", metavar=""
    )
    subparsers.required = True
    parser_status = subparsers.add_parser(
        "status", help="current status of all Ubuntu Advantage services"
    )
    parser_status.set_defaults(action=action_status)
    status_parser(parser_status)
    parser_attach = subparsers.add_parser(
        "attach",
        help="attach this machine to an Ubuntu Advantage subscription",
    )
    attach_parser(parser_attach)
    parser_attach.set_defaults(action=action_attach)
    parser_auto_attach = subparsers.add_parser(
        "auto-attach",
        help="automatically attach Ubuntu Advantage on supported platforms",
    )
    auto_attach_parser(parser_auto_attach)
    parser_auto_attach.set_defaults(action=action_auto_attach)
    parser_detach = subparsers.add_parser(
        "detach",
        help="remove this machine from an Ubuntu Advantage subscription",
    )
    detach_parser(parser_detach)
    parser_detach.set_defaults(action=action_detach)
    parser_enable = subparsers.add_parser(
        "enable",
        help="enable a specific Ubuntu Advantage service on this machine",
    )
    enable_parser(parser_enable)
    parser_enable.set_defaults(action=action_enable)
    parser_disable = subparsers.add_parser(
        "disable",
        help="disable a specific Ubuntu Advantage service on this machine",
    )
    disable_parser(parser_disable)
    parser_disable.set_defaults(action=action_disable)
    parser_refresh = subparsers.add_parser(
        "refresh",
        help="refresh Ubuntu Advantage services from contracts server",
    )
    parser_refresh.set_defaults(action=action_refresh)
    refresh_parser(parser_refresh)
    parser_fix = subparsers.add_parser(
        "fix",
        help="check for and mitigate the impact of a CVE/USN on this system",
    )
    parser_fix.set_defaults(action=action_fix)
    fix_parser(parser_fix)
    parser_version = subparsers.add_parser(
        "version", help="show version of {}".format(NAME)
    )
    parser_version.set_defaults(action=print_version)
    parser_help = subparsers.add_parser(
        "help", help="show this help message and exit"
    )
    help_parser(parser_help)
    parser_help.set_defaults(action=action_help)

    return parser


def action_status(args, cfg):
    if not cfg:
        cfg = config.UAConfig()
    show_beta = args.all if args else False
    status = cfg.status(show_beta=show_beta)
    active_value = ua_status.UserFacingConfigStatus.ACTIVE.value
    config_active = bool(status["configStatus"] == active_value)
    if args and args.wait and config_active:
        while status["configStatus"] == active_value:
            print(".", end="")
            time.sleep(1)
            status = cfg.status(show_beta=show_beta)
        print("")
    if args and args.format == "json":
        if status["expires"] != ua_status.UserFacingStatus.INAPPLICABLE.value:
            status["expires"] = str(status["expires"])
        print(json.dumps(status))
    else:
        output = ua_status.format_tabular(status)
        # Replace our Unicode dash with an ASCII dash if we aren't going to be
        # writing to a utf-8 output; see
        # https://github.com/CanonicalLtd/ubuntu-advantage-client/issues/859
        if (
            sys.stdout.encoding is None
            or "UTF-8" not in sys.stdout.encoding.upper()
        ):
            output = output.replace("\u2014", "-")
        print(output)
    return 0


def get_version(_args=None, _cfg=None):
    if _cfg is None:
        _cfg = config.UAConfig()

    return version.get_version(features=_cfg.features)


def print_version(_args=None, _cfg=None):
    print(get_version(_args, _cfg))


@assert_root
@assert_attached()
@assert_lock_file("ua refresh")
def action_refresh(args, cfg):
    try:
        contract.request_updated_contract(cfg)
    except util.UrlError as exc:
        with util.disable_log_to_console():
            logging.exception(exc)
        raise exceptions.UserFacingError(ua_status.MESSAGE_REFRESH_FAILURE)

    print(ua_status.MESSAGE_REFRESH_SUCCESS)
    return 0


def action_help(args, cfg):
    service = args.service
    show_all = args.all

    if not service:
        get_parser().print_help(show_all=show_all)
        return 0

    if not cfg:
        cfg = config.UAConfig()

    help_response = cfg.help(service)

    if args.format == "json":
        print(json.dumps(help_response))
    else:
        for key, value in help_response.items():
            print("{}:\n{}\n".format(key.title(), value))

    return 0


def setup_logging(console_level, log_level, log_file=None):
    """Setup console logging and debug logging to log_file"""
    if log_file is None:
        log_file = config.CONFIG_DEFAULTS["log_file"]
    console_formatter = util.LogFormatter()
    log_formatter = logging.Formatter(DEFAULT_LOG_FORMAT)
    root = logging.getLogger()
    root.setLevel(log_level)
    # Setup console logging
    stderr_found = False
    for handler in root.handlers:
        if hasattr(handler, "stream") and hasattr(handler.stream, "name"):
            if handler.stream.name == "<stderr>":
                handler.setLevel(console_level)
                handler.setFormatter(console_formatter)
                handler.set_name("console")  # Used to disable console logging
                stderr_found = True
                break
    if not stderr_found:
        console = logging.StreamHandler(sys.stderr)
        console.setFormatter(console_formatter)
        console.setLevel(console_level)
        console.set_name("console")  # Used to disable console logging
        root.addHandler(console)
    if os.getuid() == 0:
        # Setup readable-by-root-only debug file logging if running as root
        log_file_path = pathlib.Path(log_file)
        log_file_path.touch()
        log_file_path.chmod(0o600)

        filehandler = logging.FileHandler(log_file)
        filehandler.setLevel(log_level)
        filehandler.setFormatter(log_formatter)
        root.addHandler(filehandler)


def main_error_handler(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except KeyboardInterrupt:
            with util.disable_log_to_console():
                logging.error("KeyboardInterrupt")
            print("Interrupt received; exiting.", file=sys.stderr)
            if _CLEAR_LOCK_FILE:
                _CLEAR_LOCK_FILE("lock")
            sys.exit(1)
        except util.UrlError as exc:
            with util.disable_log_to_console():
                msg_args = {"url": exc.url, "error": exc}
                if exc.url:
                    msg_tmpl = ua_status.LOG_CONNECTIVITY_ERROR_WITH_URL_TMPL
                else:
                    msg_tmpl = ua_status.LOG_CONNECTIVITY_ERROR_TMPL
                logging.exception(msg_tmpl.format(**msg_args))
            print(ua_status.MESSAGE_CONNECTIVITY_ERROR, file=sys.stderr)
            if _CLEAR_LOCK_FILE:
                _CLEAR_LOCK_FILE("lock")
            sys.exit(1)
        except exceptions.UserFacingError as exc:
            with util.disable_log_to_console():
                logging.error(exc.msg)
            print("{}".format(exc.msg), file=sys.stderr)
            if _CLEAR_LOCK_FILE:
                if not isinstance(exc, exceptions.LockHeldError):
                    # Only clear the lock if it is ours.
                    _CLEAR_LOCK_FILE("lock")
            sys.exit(exc.exit_code)
        except Exception:
            with util.disable_log_to_console():
                logging.exception("Unhandled exception, please file a bug")
            if _CLEAR_LOCK_FILE:
                _CLEAR_LOCK_FILE("lock")
            print(ua_status.MESSAGE_UNEXPECTED_ERROR, file=sys.stderr)
            sys.exit(1)

    return wrapper


@main_error_handler
def main(sys_argv=None):
    if not sys_argv:
        sys_argv = sys.argv
    parser = get_parser()
    cli_arguments = sys_argv[1:]
    if not cli_arguments:
        parser.print_usage()
        print("Try 'ua --help' for more information.")
        sys.exit(1)
    args = parser.parse_args(args=cli_arguments)
    cfg = config.UAConfig()
    log_level = cfg.log_level
    console_level = logging.DEBUG if args.debug else logging.INFO
    setup_logging(console_level, log_level, cfg.log_file)
    logging.debug(
        util.redact_sensitive_logs("Executed with sys.argv: %r" % sys_argv)
    )
    return args.action(args, cfg)


if __name__ == "__main__":
    sys.exit(main())
