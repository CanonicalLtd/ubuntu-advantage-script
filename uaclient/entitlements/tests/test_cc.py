"""Tests related to uaclient.entitlement.base module."""

import copy
import itertools
import mock
import os.path
from types import MappingProxyType

import pytest

from uaclient import apt
from uaclient import config
from uaclient import status
from uaclient.entitlements.cc import CC_README, CommonCriteriaEntitlement
from uaclient.entitlements.tests.conftest import machine_token

M_REPOPATH = "uaclient.entitlements.repo."

CC_MACHINE_TOKEN = machine_token(
    entitlement_type="cc-eal",
    obligations={"enableByDefault": False},
    entitled=True,
    directives={
        "aptURL": "http://CC",
        "aptKey": "APTKEY",
        "suites": ["xenial"],
        "additionalPackages": ["ubuntu-commoncriteria"],
    },
    affordances={
        "architectures": ["x86_64", "ppc64le", "s390x"],
        "series": ["xenial"],
    },
)


PLATFORM_INFO_SUPPORTED = MappingProxyType(
    {
        "arch": "s390x",
        "series": "xenial",
        "kernel": "4.15.0-00-generic",
        "version": "16.04 LTS (Xenial Xerus)",
    }
)


class TestCommonCriteriaEntitlementUserFacingStatus:
    @pytest.mark.parametrize(
        "arch,series,version,details",
        (
            (
                "arm64",
                "xenial",
                "16.04 LTS (Xenial Xerus)",
                "CC EAL2 is not available for platform arm64.\n"
                "Supported platforms are: x86_64, ppc64le, s390x.",
            ),
            (
                "s390x",
                "trusty",
                "14.04 LTS (Trusty Tahr)",
                "CC EAL2 is not available for Ubuntu 14.04 LTS"
                " (Trusty Tahr).",
            ),
        ),
    )
    @mock.patch(M_REPOPATH + "os.getuid", return_value=0)
    @mock.patch("uaclient.util.get_platform_info")
    def test_inapplicable_on_invalid_affordances(
        self, m_platform_info, m_getuid, arch, series, version, details, tmpdir
    ):
        """Test invalid affordances result in inapplicable status."""
        unsupported_info = copy.deepcopy(dict(PLATFORM_INFO_SUPPORTED))
        unsupported_info["arch"] = arch
        unsupported_info["series"] = series
        unsupported_info["version"] = version
        m_platform_info.return_value = unsupported_info
        cfg = config.UAConfig(cfg={"data_dir": tmpdir.strpath})
        cfg.write_cache("machine-token", CC_MACHINE_TOKEN)
        entitlement = CommonCriteriaEntitlement(cfg)
        uf_status, uf_status_details = entitlement.user_facing_status()
        assert status.UserFacingStatus.INAPPLICABLE == uf_status
        assert details == uf_status_details


class TestCommonCriteriaEntitlementCanEnable:
    @mock.patch("uaclient.util.subp", return_value=("", ""))
    @mock.patch("uaclient.util.get_platform_info")
    def test_can_enable_true_on_entitlement_inactive(
        self, m_platform_info, _m_subp, capsys, tmpdir
    ):
        """When entitlement is INACTIVE, can_enable returns True."""
        m_platform_info.return_value = PLATFORM_INFO_SUPPORTED
        cfg = config.UAConfig(cfg={"data_dir": tmpdir.strpath})
        cfg.write_cache("machine-token", CC_MACHINE_TOKEN)
        entitlement = CommonCriteriaEntitlement(cfg, allow_beta=True)
        uf_status, uf_status_details = entitlement.user_facing_status()
        assert status.UserFacingStatus.INACTIVE == uf_status
        details = "{} is not configured".format(entitlement.title)
        assert details == uf_status_details
        assert True is entitlement.can_enable()
        assert ("", "") == capsys.readouterr()


class TestCommonCriteriaEntitlementEnable:

    # Paramterize True/False for apt_transport_https and ca_certificates
    @pytest.mark.parametrize(
        "apt_transport_https,ca_certificates",
        itertools.product([False, True], repeat=2),
    )
    @mock.patch("uaclient.util.should_reboot")
    @mock.patch("uaclient.util.subp")
    @mock.patch("uaclient.util.get_platform_info")
    def test_enable_configures_apt_sources_and_auth_files(
        self,
        m_platform_info,
        m_subp,
        m_should_reboot,
        capsys,
        tmpdir,
        apt_transport_https,
        ca_certificates,
    ):
        """When entitled, configure apt repo auth token, pinning and url."""
        m_subp.return_value = ("fakeout", "")
        m_should_reboot.return_value = False
        original_exists = os.path.exists

        def fake_platform(key=None):
            if key == "series":
                return PLATFORM_INFO_SUPPORTED[key]
            return PLATFORM_INFO_SUPPORTED

        def exists(path):
            if path == apt.APT_METHOD_HTTPS_FILE:
                return not apt_transport_https
            elif path == apt.CA_CERTIFICATES_FILE:
                return not ca_certificates
            elif not path.startswith(tmpdir.strpath):
                raise Exception(
                    "os.path.exists call outside of tmpdir: {}".format(path)
                )
            return original_exists(path)

        m_platform_info.side_effect = fake_platform
        cfg = config.UAConfig(cfg={"data_dir": tmpdir.strpath})
        cfg.write_cache("machine-token", CC_MACHINE_TOKEN)
        entitlement = CommonCriteriaEntitlement(cfg, allow_beta=True)

        with mock.patch("uaclient.apt.add_auth_apt_repo") as m_add_apt:
            with mock.patch("uaclient.apt.add_ppa_pinning") as m_add_pin:
                with mock.patch(
                    M_REPOPATH + "os.path.exists", side_effect=exists
                ):
                    assert True is entitlement.enable()

        add_apt_calls = [
            mock.call(
                "/etc/apt/sources.list.d/ubuntu-cc-eal.list",
                "http://CC",
                "{}-token".format(entitlement.name),
                ["xenial"],
                entitlement.repo_key_file,
            )
        ]

        subp_apt_cmds = [
            mock.call(
                ["apt-cache", "policy"],
                capture=True,
                retry_sleeps=apt.APT_RETRIES,
                env={},
            )
        ]

        prerequisite_pkgs = []
        if apt_transport_https:
            prerequisite_pkgs.append("apt-transport-https")
        if ca_certificates:
            prerequisite_pkgs.append("ca-certificates")

        if prerequisite_pkgs:
            expected_stdout = "Installing prerequisites: {}\n".format(
                ", ".join(prerequisite_pkgs)
            )
            subp_apt_cmds.append(
                mock.call(
                    ["apt-get", "install", "--assume-yes"] + prerequisite_pkgs,
                    capture=True,
                    retry_sleeps=apt.APT_RETRIES,
                    env={},
                )
            )
        else:
            expected_stdout = ""

        subp_apt_cmds.extend(
            [
                mock.call(
                    ["apt-get", "update"],
                    capture=True,
                    retry_sleeps=apt.APT_RETRIES,
                    env={},
                ),
                mock.call(
                    ["apt-get", "install", "--assume-yes"]
                    + entitlement.packages,
                    capture=True,
                    retry_sleeps=apt.APT_RETRIES,
                    env={},
                ),
            ]
        )

        assert add_apt_calls == m_add_apt.call_args_list
        # No apt pinning for cc
        assert [] == m_add_pin.call_args_list
        assert 1 == m_should_reboot.call_count
        assert subp_apt_cmds == m_subp.call_args_list
        expected_stdout += "\n".join(
            [
                "Updating package lists",
                "(This will download more than 500MB of packages, so may take"
                " some time.)",
                "Installing CC EAL2 packages",
                "CC EAL2 enabled",
                "Please follow instructions in {} to configure EAL2\n".format(
                    CC_README
                ),
            ]
        )
        assert (expected_stdout, "") == capsys.readouterr()
