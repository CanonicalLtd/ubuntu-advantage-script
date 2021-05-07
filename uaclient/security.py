import copy
import itertools
import os
import socket
import textwrap

from collections import defaultdict
from datetime import datetime

from uaclient import apt
from uaclient.config import UAConfig
from uaclient.clouds.identity import (
    CLOUD_TYPE_TO_TITLE,
    PRO_CLOUDS,
    get_cloud_type,
)
from uaclient import exceptions
from uaclient import status
from uaclient import serviceclient
from uaclient import util
from uaclient.entitlements import ENTITLEMENT_CLASS_BY_NAME
from uaclient.defaults import BASE_UA_URL, PRINT_WRAP_WIDTH

try:
    from typing import Any, Dict, List, Optional, Tuple  # noqa: F401
except ImportError:
    # typing isn't available on trusty, so ignore its absence
    pass


CVE_OR_USN_REGEX = (
    r"((CVE|cve)-\d{4}-\d{4,7}$|(USN|usn|LSN|lsn)-\d{1,5}-\d{1,2}$)"
)

API_V1_CVES = "cves.json"
API_V1_CVE_TMPL = "cves/{cve}.json"
API_V1_NOTICES = "notices.json"
API_V1_NOTICE_TMPL = "notices/{notice}.json"

UBUNTU_STANDARD_UPDATES_POCKET = "Ubuntu standard updates"
UA_INFRA_POCKET = "UA Infra"
UA_APPS_POCKET = "UA Apps"


class SecurityAPIError(util.UrlError):
    def __init__(self, e, error_response):
        super().__init__(e, e.code, e.headers, e.url)
        self.message = error_response.get("message", "")

    def __contains__(self, error_code):
        return bool(error_code in self.message)

    def __get__(self, error_str, default=None):
        if error_str in self.message:
            return self.message
        return default

    def __str__(self):
        prefix = super().__str__()
        details = [self.message]
        if details:
            return prefix + ": [" + self.url + "] " + ", ".join(details)
        return prefix + ": [" + self.url + "]"


class UASecurityClient(serviceclient.UAServiceClient):

    url_timeout = 20
    cfg_url_base_attr = "security_url"
    api_error_cls = SecurityAPIError

    def _get_query_params(
        self, query_params: "Dict[str, Any]"
    ) -> "Dict[str, Any]":
        """
        Update query params with data from feature config.
        """
        extra_security_params = self.cfg.cfg.get("features", {}).get(
            "extra_security_params", {}
        )

        if query_params:
            query_params.update(extra_security_params)
            return query_params

        return extra_security_params

    @util.retry(socket.timeout, retry_sleeps=[1, 3, 5])
    def request_url(
        self, path, data=None, headers=None, method=None, query_params=None
    ):
        query_params = self._get_query_params(query_params)
        return super().request_url(
            path=path,
            data=data,
            headers=headers,
            method=method,
            query_params=query_params,
        )

    def get_cves(
        self,
        query: "Optional[str]" = None,
        priority: "Optional[str]" = None,
        package: "Optional[str]" = None,
        limit: "Optional[int]" = None,
        offset: "Optional[int]" = None,
        component: "Optional[str]" = None,
        version: "Optional[str]" = None,
        status: "Optional[List[str]]" = None,
    ) -> "List[CVE]":
        """Query to match multiple-CVEs.

        @return: List of CVE instances based on the the JSON response.
        """
        query_params = {
            "q": query,
            "priority": priority,
            "package": package,
            "limit": limit,
            "offset": offset,
            "component": component,
            "version": version,
            "status": status,
        }
        cves_response, _headers = self.request_url(
            API_V1_CVES, query_params=query_params
        )
        return [CVE(client=self, response=cve_md) for cve_md in cves_response]

    def get_cve(self, cve_id: str) -> "CVE":
        """Query to match single-CVE.

        @return: CVE instance for JSON response from the Security API.
        """
        cve_response, _headers = self.request_url(
            API_V1_CVE_TMPL.format(cve=cve_id)
        )
        return CVE(client=self, response=cve_response)

    def get_notices(
        self,
        details: "Optional[str]" = None,
        release: "Optional[str]" = None,
        limit: "Optional[int]" = None,
        offset: "Optional[int]" = None,
        order: "Optional[str]" = None,
    ) -> "List[USN]":
        """Query to match multiple-USNs.

        @return: Sorted list of USN instances based on the the JSON response.
        """
        query_params = {
            "details": details,
            "release": release,
            "limit": limit,
            "offset": offset,
            "order": order,
        }
        usns_response, _headers = self.request_url(
            API_V1_NOTICES, query_params=query_params
        )
        return sorted(
            [
                USN(client=self, response=usn_md)
                for usn_md in usns_response.get("notices", [])
                if details is None or details in usn_md.get("cves_ids", [])
            ],
            key=lambda x: x.id,
        )

    def get_notice(self, notice_id: str) -> "USN":
        """Query to match single-USN.

        @return: USN instance representing the JSON response.
        """
        notice_response, _headers = self.request_url(
            API_V1_NOTICE_TMPL.format(notice=notice_id)
        )
        return USN(client=self, response=notice_response)


# Model for Security API responses
class CVEPackageStatus:
    """Class representing specific CVE PackageStatus on an Ubuntu series"""

    def __init__(self, cve_response: "Dict[str, Any]"):
        self.response = cve_response

    @property
    def description(self):
        return self.response["description"]

    @property
    def fixed_version(self):
        return self.description

    @property
    def pocket(self):
        return self.response["pocket"]

    @property
    def release_codename(self):
        return self.response["release_codename"]

    @property
    def status(self):
        return self.response["status"]

    @property
    def status_message(self):
        if self.status == "needed":
            return "Sorry, no fix is available yet."
        elif self.status == "needs-triage":
            return "Ubuntu security engineers are investigating this issue."
        elif self.status == "pending":
            return "A fix is coming soon. Try again tomorrow."
        elif self.status in ("ignored", "deferred"):
            return "Sorry, no fix is available."
        elif self.status == "DNE":
            return "Source package does not exist on this release."
        elif self.status == "not-affected":
            return "Source package is not affected on this release."
        elif self.status == "released":
            return status.MESSAGE_SECURITY_FIX_RELEASE_STREAM.format(
                fix_stream=self.pocket_source
            )
        return "UNKNOWN: {}".format(self.status)

    @property
    def requires_ua(self) -> bool:
        """Return True if the package requires an active UA subscription."""
        return bool(self.pocket_source != UBUNTU_STANDARD_UPDATES_POCKET)

    @property
    def pocket_source(self):
        """Human-readable string representing where the fix is published."""
        if self.pocket == "esm-infra":
            fix_source = UA_INFRA_POCKET
        elif self.pocket == "esm-apps":
            fix_source = UA_APPS_POCKET
        elif self.pocket in ("updates", "security"):
            fix_source = UBUNTU_STANDARD_UPDATES_POCKET
        else:
            # TODO(GH: #1376 drop this when esm* pockets supplied by API)
            if "esm" in self.fixed_version:
                fix_source = UA_INFRA_POCKET
            else:
                fix_source = UBUNTU_STANDARD_UPDATES_POCKET
        return fix_source


class CVE:
    """Class representing CVE response from the SecurityClient"""

    def __init__(self, client: UASecurityClient, response: "Dict[str, Any]"):
        self.response = response
        self.client = client

    def __eq__(self, other) -> bool:
        if not isinstance(other, CVE):
            return False
        return self.response == other.response

    @property
    def id(self):
        return self.response.get("id", "UNKNOWN_CVE_ID").upper()

    def get_url_header(self):
        """Return a string representing the URL for this cve."""
        title = self.description
        for notice in self.notices:
            # Only look at the most recent USN title
            title = notice.title
            break
        lines = [
            "{issue}: {title}".format(issue=self.id, title=title),
            "https://ubuntu.com/security/{}".format(self.id),
        ]
        return "\n".join(lines)

    @property
    def notices_ids(self) -> "List[str]":
        return self.response.get("notices_ids", [])

    @property
    def notices(self) -> "List[USN]":
        """Return a list of USN instances from API response 'notices'.

        Cache the value to avoid extra work on multiple calls.
        """
        if not hasattr(self, "_notices"):
            self._notices = sorted(
                [
                    USN(self.client, notice)
                    for notice in self.response.get("notices", [])
                ],
                key=lambda n: n.id,
                reverse=True,
            )
        return self._notices

    @property
    def description(self):
        return self.response.get("description")

    @property
    def packages_status(self) -> "Dict[str, CVEPackageStatus]":
        """Dict of package status dicts for the current Ubuntu series.

        Top-level keys are source packages names and each value is a
        CVEPackageStatus object
        """
        if hasattr(self, "_packages_status"):
            return self._packages_status  # type: ignore
        self._packages_status = {}
        series = util.get_platform_info()["series"]
        for package in self.response["packages"]:
            for pkg_status in package["statuses"]:
                if pkg_status["release_codename"] == series:
                    self._packages_status[package["name"]] = CVEPackageStatus(
                        pkg_status
                    )
        return self._packages_status


class USN:
    """Class representing USN response from the SecurityClient"""

    def __init__(self, client: UASecurityClient, response: "Dict[str, Any]"):
        self.response = response
        self.client = client

    def __eq__(self, other) -> bool:
        if not isinstance(other, USN):
            return False
        return self.response == other.response

    @property
    def id(self) -> str:
        return self.response.get("id", "UNKNOWN_USN_ID").upper()

    @property
    def cves_ids(self) -> "List[str]":
        """List of CVE IDs related to this USN."""
        return self.response.get("cves_ids", [])

    @property
    def cves(self) -> "List[CVE]":
        """List of CVE instances based on API response 'cves' key.

        Cache the values to avoid extra work for multiple call-sites.
        """
        if not hasattr(self, "_cves"):
            self._cves = sorted(
                [
                    CVE(self.client, cve)
                    for cve in self.response.get("cves", [])
                ],
                key=lambda n: n.id,
                reverse=True,
            )  # type: List[CVE]
        return self._cves

    @property
    def title(self):
        return self.response.get("title")

    def get_url_header(self):
        """Return a string representing the URL for this notice."""
        lines = [
            "{issue}: {title}".format(issue=self.id, title=self.title),
            "Found CVEs:",
        ]
        for cve in self.cves_ids:
            lines.append("https://ubuntu.com/security/{}".format(cve))
        return "\n".join(lines)

    @property
    def release_packages(self) -> "Dict[str, Dict[str, Dict[str, str]]]":
        """Binary package information available for this release.


        Reformat the USN.release_packages response to key it based on source
        package name and related binary package names.

        :return: Dict keyed by source package name. The second-level key will
            be binary package names generated from that source package and the
            values will be the dict response from USN.release_packages for
            that binary package. The binary metadata contains the following
            keys: name, version.
            Optional additional keys: pocket and component.
        """
        if hasattr(self, "_release_packages"):
            return self._release_packages
        series = util.get_platform_info()["series"]
        self._release_packages = {}  # type: Dict[str, Dict[str, Any]]
        # Organize source and binary packages under a common source package key
        for pkg in self.response.get("release_packages", {}).get(series, []):
            if pkg.get("is_source"):
                # Create a "source" key under src_pkg_name with API response
                if pkg["name"] in self._release_packages:
                    if "source" in self._release_packages[pkg["name"]]:
                        raise exceptions.SecurityAPIMetadataError(
                            "{usn} metadata defines duplicate source packages"
                            " {pkg}".format(usn=self.id, pkg=pkg["name"]),
                            issue_id=self.id,
                        )
                    self._release_packages[pkg["name"]]["source"] = pkg
                else:
                    self._release_packages[pkg["name"]] = {"source": pkg}
            else:
                # is_source == False or None, then this is a binary package.
                # If processed before a source item, the top-level key will
                # not exist yet.
                # TODO(GH: 1465: determine if this is expected on kern pkgs)
                if not pkg.get("source_link"):
                    raise exceptions.SecurityAPIMetadataError(
                        "{issue} metadata does not define release_packages"
                        " source_link for {bin_pkg}.".format(
                            issue=self.id, bin_pkg=pkg["name"]
                        ),
                        issue_id=self.id,
                    )
                elif "/" not in pkg["source_link"]:
                    raise exceptions.SecurityAPIMetadataError(
                        "{issue} metadata has unexpected release_packages"
                        " source_link value for {bin_pkg}: {link}".format(
                            issue=self.id,
                            bin_pkg=pkg["name"],
                            link=pkg["source_link"],
                        ),
                        issue_id=self.id,
                    )
                source_pkg_name = pkg["source_link"].split("/")[-1]
                if source_pkg_name not in self._release_packages:
                    self._release_packages[source_pkg_name] = {}
                self._release_packages[source_pkg_name][pkg["name"]] = pkg
        return self._release_packages


def query_installed_source_pkg_versions() -> "Dict[str, Dict[str, str]]":
    """Return a dict of all source packages installed on the system.

    The dict keys will be source package name: "krb5". The value will be a dict
    with keys binary_pkg and version.
    """
    series = util.get_platform_info()["series"]
    if series == "trusty":
        status_field = "${Status}"
    else:
        status_field = "${db:Status-Status}"
    out, _err = util.subp(
        [
            "dpkg-query",
            "-f=${Package},${Source},${Version}," + status_field + "\n",
            "-W",
        ]
    )
    installed_packages = {}  # type: Dict[str, Dict[str, str]]
    for pkg_line in out.splitlines():
        pkg_name, source_pkg_name, pkg_version, status = pkg_line.split(",")
        if not source_pkg_name:
            # some package don't define the Source
            source_pkg_name = pkg_name
        if "installed" not in status:
            continue
        if source_pkg_name in installed_packages:
            installed_packages[source_pkg_name][pkg_name] = pkg_version
        else:
            installed_packages[source_pkg_name] = {pkg_name: pkg_version}
    return installed_packages


def merge_usn_released_binary_package_versions(
    usns: "List[USN]", beta_pockets: "Dict[str, bool]"
) -> "Dict[str,  Dict[str, Dict[str, str]]]":
    """Walk related USNs, merging the released binary package versions.

    For each USN, iterate over release_packages to collect released binary
        package names and required fix version. If multiple related USNs
        require differnt version fixes to the same binary package, track the
        maximum version required across all USNs.

    :param usns: List of USN response instances from which to calculate merge.
    :param beta_pockets: Dict keyed on service name: esm-infra, esm-apps
        the values of which will be true of USN response instances
        from which to calculate merge.

    :return: Dict keyed by source package name. Under each source package will
        be a dict with binary package name as keys and binary package metadata
        as the value.
    """
    usn_pkg_versions = {}
    for usn in usns:
        # Aggregate USN.release_package binary versions into usn_pkg_versions
        for src_pkg, binary_pkg_versions in usn.release_packages.items():
            public_bin_pkg_versions = {
                bin_pkg_name: bin_pkg_md
                for bin_pkg_name, bin_pkg_md in binary_pkg_versions.items()
                if False
                is beta_pockets.get(bin_pkg_md.get("pocket", "None"), False)
            }
            if src_pkg not in usn_pkg_versions and public_bin_pkg_versions:
                usn_pkg_versions[src_pkg] = public_bin_pkg_versions
            elif src_pkg in usn_pkg_versions:
                # Since src_pkg exists, only record this USN's binary version
                # when it is greater than the previous version in usn_src_pkg.
                usn_src_pkg = usn_pkg_versions[src_pkg]
                for bin_pkg, binary_pkg_md in public_bin_pkg_versions.items():
                    if bin_pkg not in usn_src_pkg:
                        usn_src_pkg[bin_pkg] = binary_pkg_md
                    else:
                        prev_version = usn_src_pkg[bin_pkg]["version"]
                        current_version = binary_pkg_md["version"]
                        if not version_cmp_le(current_version, prev_version):
                            # binary_version is greater than prev_version
                            usn_src_pkg[bin_pkg] = binary_pkg_md
    return usn_pkg_versions


def fix_security_issue_id(cfg: UAConfig, issue_id: str) -> None:
    issue_id = issue_id.upper()
    client = UASecurityClient(cfg=cfg)
    installed_packages = query_installed_source_pkg_versions()

    # Used to filter out beta pockets during merge_usns
    beta_pockets = {
        "esm-apps": _is_pocket_used_by_beta_service("esm-apps", cfg),
        "esm-infra": _is_pocket_used_by_beta_service("esm-infra", cfg),
    }

    if "CVE" in issue_id:
        try:
            cve = client.get_cve(cve_id=issue_id)
            usns = client.get_notices(details=issue_id)
        except SecurityAPIError as e:
            msg = str(e)
            if "not found" in msg.lower():
                msg = status.MESSAGE_SECURITY_FIX_NOT_FOUND_ISSUE.format(
                    issue_id=issue_id
                )
            raise exceptions.UserFacingError(msg)
        affected_pkg_status = get_cve_affected_source_packages_status(
            cve=cve, installed_packages=installed_packages
        )
        print(cve.get_url_header())
        usn_released_pkgs = merge_usn_released_binary_package_versions(
            usns, beta_pockets
        )
    else:  # USN
        related_usns = {}
        try:
            usn = client.get_notice(notice_id=issue_id)
            for cve in usn.cves:
                for related_usn_id in cve.notices_ids:
                    if related_usn_id not in related_usns:
                        related_usns[related_usn_id] = client.get_notice(
                            notice_id=related_usn_id
                        )
            usns = list(sorted(related_usns.values(), key=lambda x: x.id))
        except SecurityAPIError as e:
            msg = str(e)
            if "not found" in msg.lower():
                msg = status.MESSAGE_SECURITY_FIX_NOT_FOUND_ISSUE.format(
                    issue_id=issue_id
                )
            raise exceptions.UserFacingError(msg)
        affected_pkg_status = get_usn_affected_packages_status(
            usn=usn, installed_packages=installed_packages
        )
        usn_released_pkgs = merge_usn_released_binary_package_versions(
            usns, beta_pockets
        )
        print(usn.get_url_header())
        related_cves = set(itertools.chain(*[u.cves_ids for u in usns]))
        if not related_cves:
            raise exceptions.SecurityAPIMetadataError(
                "{} metadata defines no related CVEs.".format(issue_id),
                issue_id=issue_id,
            )
        if not usn.response["release_packages"]:
            # Since usn.release_packages filters to our current release only
            # check overall metadata and error if empty.
            raise exceptions.SecurityAPIMetadataError(
                "{} metadata defines no fixed package versions.".format(
                    issue_id
                ),
                issue_id=issue_id,
            )
    prompt_for_affected_packages(
        cfg=cfg,
        issue_id=issue_id,
        affected_pkg_status=affected_pkg_status,
        installed_packages=installed_packages,
        usn_released_pkgs=usn_released_pkgs,
    )


def get_usn_affected_packages_status(
    usn: USN, installed_packages: "Dict[str, Dict[str, str]]"
) -> "Dict[str, CVEPackageStatus]":
    """Walk CVEs related to a USN and return a dict of all affected packages.

    :return: Dict keyed on source package name, with active CVEPackageStatus
        for the current Ubuntu release.
    """
    affected_pkgs = {}  # type: Dict[str, CVEPackageStatus]
    for cve in usn.cves:
        for pkg_name, pkg_status in get_cve_affected_source_packages_status(
            cve, installed_packages
        ).items():
            if pkg_name not in affected_pkgs:
                affected_pkgs[pkg_name] = pkg_status
            else:
                current_ver = affected_pkgs[pkg_name].fixed_version
                if not version_cmp_le(current_ver, pkg_status.fixed_version):
                    affected_pkgs[pkg_name] = pkg_status
    return affected_pkgs


def get_cve_affected_source_packages_status(
    cve: CVE, installed_packages: "Dict[str, Dict[str, str]]"
) -> "Dict[str, CVEPackageStatus]":
    """Get a dict of any CVEPackageStatuses affecting this Ubuntu release.

    :return: Dict of active CVEPackageStatus keyed by source package names.
    """
    affected_pkg_versions = {}
    for source_pkg, package_status in cve.packages_status.items():
        if package_status.status == "not-affected":
            continue
        if source_pkg in installed_packages:
            affected_pkg_versions[source_pkg] = package_status
    return affected_pkg_versions


def print_affected_packages_header(
    issue_id: str, affected_pkg_status: "Dict[str, CVEPackageStatus]"
):
    """Print header strings describing affected packages related to a CVE/USN.

    :param issue_id: String of USN or CVE issue id.
    :param affected_pkg_status: Dict keyed on source package name, with active
        CVEPackageStatus for the current Ubuntu release.
    """
    count = len(affected_pkg_status)
    if count == 0:
        print(
            status.MESSAGE_SECURITY_AFFECTED_PKGS.format(
                count="No", plural_str="s are"
            )
            + "."
        )
        print(status.MESSAGE_SECURITY_ISSUE_UNAFFECTED.format(issue=issue_id))
        return

    if count == 1:
        plural_str = " is"
    else:
        plural_str = "s are"
    msg = (
        status.MESSAGE_SECURITY_AFFECTED_PKGS.format(
            count=count, plural_str=plural_str
        )
        + ": "
        + ", ".join(sorted(affected_pkg_status.keys()))
    )
    print(textwrap.fill(msg, width=PRINT_WRAP_WIDTH, subsequent_indent="    "))


def override_usn_release_package_status(
    pkg_status: CVEPackageStatus,
    usn_src_released_pkgs: "Dict[str, Dict[str, str]]",
) -> CVEPackageStatus:
    """Parse release status based on both pkg_status and USN.release_packages.

    Since some source packages in universe are not represented in
    CVEPackageStatus, rely on presence of such source packages in
    usn_src_released_pkgs to represent package as a "released" status.

    :param pkg_status: the CVEPackageStatus for this source package.
    :param usn_src_released_pkgs: The USN.release_packages representing only
       this source package. Normally, release_packages would have data on
       multiple source packages.

    :return: Tuple of:
        human-readable status message, boolean whether released,
        boolean whether the fix requires access to UA
    """

    usn_pkg_status = copy.deepcopy(pkg_status)
    if usn_src_released_pkgs and usn_src_released_pkgs.get("source"):
        usn_pkg_status.response["status"] = "released"
        usn_pkg_status.response["description"] = usn_src_released_pkgs[
            "source"
        ]["version"]
        for pkg_name, usn_released_pkg in usn_src_released_pkgs.items():
            # Copy the pocket from any valid binary package
            pocket = usn_released_pkg.get("pocket")
            if pocket:
                usn_pkg_status.response["pocket"] = pocket
                break
    return usn_pkg_status


def group_by_usn_package_status(affected_pkg_status, usn_released_pkgs):
    status_groups = {}
    for src_pkg, pkg_status in sorted(affected_pkg_status.items()):
        usn_released_src = usn_released_pkgs.get(src_pkg, {})
        usn_pkg_status = override_usn_release_package_status(
            pkg_status, usn_released_src
        )
        status_group = usn_pkg_status.status.replace("ignored", "deferred")
        if status_group not in status_groups:
            status_groups[status_group] = []
        status_groups[status_group].append((src_pkg, usn_pkg_status))
    return status_groups


def _format_packages_message(
    pkg_status_list: "List[Tuple[str, CVEPackageStatus]]",
    pkg_index: int,
    num_pkgs: int,
) -> str:
    """Format the packages and status to an user friendly message."""
    if not pkg_status_list:
        return ""

    msg_index = []
    src_pkgs = []
    for src_pkg, pkg_status in pkg_status_list:
        pkg_index += 1
        msg_index.append("{}/{}".format(pkg_index, num_pkgs))
        src_pkgs.append(src_pkg)

    msg_header = textwrap.fill(
        "{} {}:".format(
            "(" + ", ".join(msg_index) + ")", ", ".join(sorted(src_pkgs))
        ),
        width=PRINT_WRAP_WIDTH,
        subsequent_indent="    ",
    )
    return "{}\n{}".format(msg_header, pkg_status.status_message)


def _get_service_for_pocket(pocket: str, cfg: UAConfig):
    service_to_check = "no-service-needed"
    if pocket == UA_INFRA_POCKET:
        service_to_check = "esm-infra"
    elif pocket == UA_APPS_POCKET:
        service_to_check = "esm-apps"

    ent_cls = ENTITLEMENT_CLASS_BY_NAME.get(service_to_check)
    return ent_cls(cfg) if ent_cls else None


def _is_pocket_used_by_beta_service(pocket: str, cfg: UAConfig) -> bool:
    """Check if the pocket where the fix is at belongs to a beta service."""
    ent = _get_service_for_pocket(pocket, cfg)
    if ent:
        ent_status, _ = ent.user_facing_status()

        # If the service is already enabled, we proceed with the fix
        # even if the service is a beta stage.
        if ent_status == status.UserFacingStatus.ACTIVE:
            return False

        return ent.is_beta

    return False


def _handle_released_package_fixes(
    cfg: UAConfig,
    src_pocket_pkgs: "Dict[str, List[Tuple[str, CVEPackageStatus]]]",
    binary_pocket_pkgs: "Dict[str, List[str]]",
    pkg_index: int,
    num_pkgs: int,
) -> "Tuple[bool, List[str], bool]":
    """Handle the packages that could be fixed and have a released status.

    :returns: Tuple of
        boolean whether all packages were successfully upgraded,
        list of strings containing the packages that were not upgraded,
        boolean whether all packages were already installed
    """
    all_already_installed = True
    upgrade_status = True
    unfixed_pkgs = []
    if src_pocket_pkgs:
        for pocket in [
            UBUNTU_STANDARD_UPDATES_POCKET,
            UA_INFRA_POCKET,
            UA_APPS_POCKET,
        ]:
            pkg_src_group = src_pocket_pkgs[pocket]
            binary_pkgs = binary_pocket_pkgs[pocket]

            if upgrade_status:
                msg = _format_packages_message(
                    pkg_status_list=pkg_src_group,
                    pkg_index=pkg_index,
                    num_pkgs=num_pkgs,
                )

                if msg:
                    print(msg)

                    if not binary_pkgs:
                        print(status.MESSAGE_SECURITY_UPDATE_INSTALLED)
                        continue
                    else:
                        # if even one pocket has binary_pkgs to install
                        # then we can't say that everything was already
                        # installed.
                        all_already_installed = False

                pkg_index += len(pkg_src_group)
                upgrade_status &= upgrade_packages_and_attach(
                    cfg, binary_pkgs, pocket
                )

            if not upgrade_status:
                unfixed_pkgs += [src_pkg for src_pkg, _ in pkg_src_group]

    return upgrade_status, unfixed_pkgs, all_already_installed


def _format_unfixed_packages_msg(unfixed_pkgs: "List[str]") -> str:
    """Format the list of unfixed packages into an message.

    :returns: A string containing the message output for the unfixed
              packages.
    """
    num_pkgs_unfixed = len(unfixed_pkgs)
    return textwrap.fill(
        "{} package{} {} still affected: {}".format(
            num_pkgs_unfixed,
            "s" if num_pkgs_unfixed > 1 else "",
            "are" if num_pkgs_unfixed > 1 else "is",
            ", ".join(sorted(unfixed_pkgs)),
        ),
        width=PRINT_WRAP_WIDTH,
        subsequent_indent="    ",
    )


def prompt_for_affected_packages(
    cfg: UAConfig,
    issue_id: str,
    affected_pkg_status: "Dict[str, CVEPackageStatus]",
    installed_packages: "Dict[str, Dict[str, str]]",
    usn_released_pkgs: "Dict[str, Dict[str, Dict[str, str]]]",
) -> None:
    """Process security CVE dict returning a CVEStatus object.

    Since CVEs point to a USN if active, get_notice may be called to fill in
    CVE title details.
    """
    count = len(affected_pkg_status)
    print_affected_packages_header(issue_id, affected_pkg_status)
    if count == 0:
        return
    fix_message = status.MESSAGE_SECURITY_ISSUE_RESOLVED.format(issue=issue_id)
    src_pocket_pkgs = defaultdict(list)
    binary_pocket_pkgs = defaultdict(list)
    pkg_index = 0

    pkg_status_groups = group_by_usn_package_status(
        affected_pkg_status, usn_released_pkgs
    )

    unfixed_pkgs = []
    for status_value, pkg_status_group in sorted(pkg_status_groups.items()):
        if status_value != "released":
            fix_message = status.MESSAGE_SECURITY_ISSUE_NOT_RESOLVED.format(
                issue=issue_id
            )
            print(
                _format_packages_message(
                    pkg_status_list=pkg_status_group,
                    pkg_index=pkg_index,
                    num_pkgs=count,
                )
            )
            pkg_index += len(pkg_status_group)
            unfixed_pkgs += [src_pkg for src_pkg, _ in pkg_status_group]
        else:
            for src_pkg, pkg_status in pkg_status_group:
                src_pocket_pkgs[pkg_status.pocket_source].append(
                    (src_pkg, pkg_status)
                )
                for binary_pkg, version in installed_packages[src_pkg].items():
                    usn_released_src = usn_released_pkgs.get(src_pkg, {})
                    if binary_pkg not in usn_released_src:
                        unfixed_pkgs += [
                            src_pkg for src_pkg, _ in pkg_status_group
                        ]
                        msg = (
                            "{issue} metadata defines no fixed version for"
                            " {pkg}.\n".format(pkg=binary_pkg, issue=issue_id)
                        )

                        msg += _format_unfixed_packages_msg(unfixed_pkgs)
                        raise exceptions.SecurityAPIMetadataError(
                            msg, issue_id
                        )
                    fixed_pkg = usn_released_src[binary_pkg]
                    fixed_version = fixed_pkg["version"]  # type: ignore
                    if not version_cmp_le(fixed_version, version):
                        binary_pocket_pkgs[pkg_status.pocket_source].append(
                            binary_pkg
                        )

    (
        fix_status,
        unfixed_pkgs_released,
        all_already_installed,
    ) = _handle_released_package_fixes(
        cfg=cfg,
        src_pocket_pkgs=src_pocket_pkgs,
        binary_pocket_pkgs=binary_pocket_pkgs,
        pkg_index=pkg_index,
        num_pkgs=count,
    )

    unfixed_pkgs += unfixed_pkgs_released

    if unfixed_pkgs:
        print(_format_unfixed_packages_msg(unfixed_pkgs))

    if fix_status:
        # fix_status is True if either:
        #  (1) we successfully installed all the packages we needed to
        #  (2) we didn't need to install any packages
        # In case (2), then all_already_installed is also True
        if all_already_installed:
            # we didn't install any packages, so we're good
            print(fix_message)
        elif util.should_reboot():
            # we successfully installed some packages, but
            # system reboot-required. This might be because
            # or our installations.
            reboot_msg = status.MESSAGE_ENABLE_REBOOT_REQUIRED_TMPL.format(
                operation="fix operation"
            )
            print(reboot_msg)
            cfg.add_notice("", reboot_msg)
            print(
                status.MESSAGE_SECURITY_ISSUE_NOT_RESOLVED.format(
                    issue=issue_id
                )
            )
        else:
            # we successfully installed some packages, and the system
            # reboot-required flag is not set, so we're good
            print(fix_message)
    else:
        print(
            status.MESSAGE_SECURITY_ISSUE_NOT_RESOLVED.format(issue=issue_id)
        )


def _inform_ubuntu_pro_existence_if_applicable() -> None:
    """Alert the user when running UA on cloud with PRO support."""
    cloud_type = get_cloud_type()
    if cloud_type in PRO_CLOUDS:
        print(
            status.MESSAGE_SECURITY_USE_PRO_TMPL.format(
                title=CLOUD_TYPE_TO_TITLE.get(cloud_type), cloud=cloud_type
            )
        )


def _run_ua_attach(cfg: UAConfig, token: str) -> bool:
    """Attach to a UA subscription with a given token.

    :return: True if attach performed without errors.
    """
    import argparse
    from uaclient import cli

    print(status.colorize_commands([["ua", "attach", token]]))
    return bool(
        0
        == cli.action_attach(
            argparse.Namespace(token=token, auto_enable=True), cfg
        )
    )


def _prompt_for_attach(cfg: UAConfig) -> bool:
    """Prompt for attach to a subscription or token.

    :return: True if attach performed.
    """
    _inform_ubuntu_pro_existence_if_applicable()
    print(status.MESSAGE_SECURITY_UPDATE_NOT_INSTALLED_SUBSCRIPTION)
    choice = util.prompt_choices(
        "Choose: [S]ubscribe at ubuntu.com [A]ttach existing token [C]ancel",
        valid_choices=["s", "a", "c"],
    )
    if choice == "c":
        return False
    if choice == "s":
        print(status.PROMPT_UA_SUBSCRIPTION_URL)
        # TODO(GH: #1413: magic subscription attach)
        input("Hit [Enter] when subscription is complete.")
    if choice in ("a", "s"):
        print(status.PROMPT_ENTER_TOKEN)
        token = input("> ")
        return _run_ua_attach(cfg, token)

    return True


def _prompt_for_enable(cfg: UAConfig, service: str) -> bool:
    """Prompt for enable a ua service.

    :return: True if enable performed.
    """
    import argparse
    from uaclient import cli

    print(status.MESSAGE_SECURITY_SERVICE_DISABLED.format(service=service))
    choice = util.prompt_choices(
        "Choose: [E]nable {} [C]ancel".format(service),
        valid_choices=["e", "c"],
    )

    if choice == "e":
        print(status.colorize_commands([["ua", "enable", service]]))
        return bool(
            0
            == cli.action_enable(
                argparse.Namespace(
                    service=[service], assume_yes=True, beta=False
                ),
                cfg,
            )
        )

    return False


def _check_subscription_for_required_service(
    pocket: str, cfg: UAConfig
) -> bool:
    """Verify if the ua subscription has the required service enabled."""
    ent = _get_service_for_pocket(pocket, cfg)

    if ent:
        ent_status, _ = ent.user_facing_status()

        if ent_status == status.UserFacingStatus.ACTIVE:
            return True

        applicability_status, _ = ent.applicability_status()
        if applicability_status == status.ApplicabilityStatus.APPLICABLE:
            if _prompt_for_enable(cfg, ent.name):
                return True
            else:
                print(
                    status.MESSAGE_SECURITY_UA_SERVICE_NOT_ENABLED.format(
                        service=ent.name
                    )
                )
        else:
            print(
                status.MESSAGE_SECURITY_UA_SERVICE_NOT_ENTITLED.format(
                    service=ent.name
                )
            )

    return False


def _prompt_for_new_token(cfg: UAConfig) -> bool:
    """Prompt for attach a new subscription token to the user.

    :return: True if attach performed.
    """
    import argparse
    from uaclient import cli

    _inform_ubuntu_pro_existence_if_applicable()
    print(status.MESSAGE_SECURITY_UPDATE_NOT_INSTALLED_EXPIRED)
    choice = util.prompt_choices(
        "Choose: [R]enew your subscription (at {}) [C]ancel".format(
            BASE_UA_URL
        ),
        valid_choices=["r", "c"],
    )
    if choice == "r":
        print(status.PROMPT_EXPIRED_ENTER_TOKEN)
        token = input("> ")
        print(status.colorize_commands([["ua", "detach"]]))
        cli.action_detach(argparse.Namespace(assume_yes=True), cfg)
        return _run_ua_attach(cfg, token)

    return False


def _check_subscription_is_expired(cfg: UAConfig) -> bool:
    """Check if user UA subscription is expired.

    :returns: True if subscription is expired and not renewed.
    """
    contract_expiry_datetime = cfg.contract_expiry_datetime
    tzinfo = contract_expiry_datetime.tzinfo
    if contract_expiry_datetime < datetime.now(tzinfo):
        return not _prompt_for_new_token(cfg)

    return False


def upgrade_packages_and_attach(
    cfg: UAConfig, upgrade_packages: "List[str]", pocket: str
) -> bool:
    """Upgrade available packages to fix a CVE.

    Upgrade all packages in upgrades_packages and, if necessary,
    prompt regarding system attach prior to upgrading UA packages.

    :return: True if package upgrade completed or unneeded, False otherwise.
    """
    if not upgrade_packages:
        return True

    if os.getuid() != 0:
        print(status.MESSAGE_SECURITY_APT_NON_ROOT)
        return False

    if pocket != UBUNTU_STANDARD_UPDATES_POCKET:
        if not cfg.is_attached:
            if not _prompt_for_attach(cfg):
                return False  # User opted to cancel
        elif _check_subscription_is_expired(cfg):
            # UA subscription is expired and the user has not
            # renewed it
            return False

        if not _check_subscription_for_required_service(pocket, cfg):
            # User subscription does not have required service enabled
            return False

    print(
        status.colorize_commands(
            [
                ["apt", "update", "&&"]
                + ["apt", "install", "--only-upgrade", "-y"]
                + upgrade_packages
            ]
        )
    )
    apt.run_apt_command(
        cmd=["apt-get", "update"], error_msg=status.MESSAGE_APT_UPDATE_FAILED
    )
    apt.run_apt_command(
        cmd=["apt-get", "install", "--only-upgrade", "-y"] + upgrade_packages,
        error_msg=status.MESSAGE_APT_INSTALL_FAILED,
        env={"DEBIAN_FRONTEND": "noninteractive"},
    )
    return True


def version_cmp_le(version1: str, version2: str) -> bool:
    """Return True when version1 is less than or equal to version2."""
    try:
        util.subp(["dpkg", "--compare-versions", version1, "le", version2])
        return True
    except util.ProcessExecutionError:
        return False
