"""Tests related to uaclient.entitlement.base module."""

import mock

import pytest

from uaclient import apt
from uaclient import status
from uaclient.entitlements.cis import CISEntitlement


M_REPOPATH = "uaclient.entitlements.repo."


@pytest.fixture
def entitlement(entitlement_factory):
    return entitlement_factory(
        CISEntitlement, allow_beta=True, additional_packages=["pkg1"]
    )


class TestCISEntitlementCanEnable:
    def test_can_enable_true_on_entitlement_inactive(
        self, capsys, entitlement
    ):
        """When entitlement is INACTIVE, can_enable returns True."""
        # Unset static affordance container check
        with mock.patch.object(
            entitlement,
            "application_status",
            return_value=(status.ApplicationStatus.DISABLED, ""),
        ):
            assert entitlement.can_enable()
        assert ("", "") == capsys.readouterr()


class TestCISEntitlementEnable:
    @mock.patch("uaclient.util.should_reboot")
    @mock.patch("uaclient.util.subp")
    @mock.patch("uaclient.util.get_platform_info")
    def test_enable_configures_apt_sources_and_auth_files(
        self, m_platform_info, m_subp, m_should_reboot, capsys, entitlement
    ):
        """When entitled, configure apt repo auth token, pinning and url."""

        def fake_platform(key=None):
            info = {"series": "xenial", "kernel": "4.15.0-00-generic"}
            if key:
                return info[key]
            return info

        m_platform_info.side_effect = fake_platform
        m_subp.return_value = ("fakeout", "")
        m_should_reboot.return_value = False

        with mock.patch(
            M_REPOPATH + "os.path.exists", mock.Mock(return_value=True)
        ):
            with mock.patch("uaclient.apt.add_auth_apt_repo") as m_add_apt:
                with mock.patch("uaclient.apt.add_ppa_pinning") as m_add_pin:
                    assert entitlement.enable()

        add_apt_calls = [
            mock.call(
                "/etc/apt/sources.list.d/ubuntu-cis.list",
                "http://CIS",
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
            ),
            mock.call(
                ["apt-get", "update"],
                capture=True,
                retry_sleeps=apt.APT_RETRIES,
                env={},
            ),
            mock.call(
                [
                    "apt-get",
                    "install",
                    "--assume-yes",
                    '-o Dpkg::Options::="--force-confdef"',
                    '-o Dpkg::Options::="--force-confold"',
                ]
                + entitlement.packages,
                capture=True,
                retry_sleeps=apt.APT_RETRIES,
                env={"DEBIAN_FRONTEND": "noninteractive"},
            ),
        ]

        assert add_apt_calls == m_add_apt.call_args_list
        # No apt pinning for cis
        assert [] == m_add_pin.call_args_list
        assert subp_apt_cmds == m_subp.call_args_list
        assert 1 == m_should_reboot.call_count
        expected_stdout = (
            "Updating package lists\n"
            "Installing CIS Audit packages\n"
            "CIS Audit enabled\n"
        )
        assert (expected_stdout, "") == capsys.readouterr()
