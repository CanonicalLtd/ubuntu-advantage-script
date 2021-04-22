import contextlib
import mock
import os.path

import pytest

from uaclient import apt
from uaclient.entitlements.esm import ESMAppsEntitlement, ESMInfraEntitlement
from uaclient import exceptions
from uaclient import util

M_PATH = "uaclient.entitlements.esm.ESMInfraEntitlement."
M_REPOPATH = "uaclient.entitlements.repo."
M_GETPLATFORM = M_REPOPATH + "util.get_platform_info"


@pytest.fixture(params=[ESMAppsEntitlement, ESMInfraEntitlement])
def entitlement(request, entitlement_factory):
    return entitlement_factory(request.param, suites=["trusty"])


class TestESMRepoPinPriority:
    @pytest.mark.parametrize(
        "esm_class, series, repo_pin_priority",
        (
            (ESMInfraEntitlement, "trusty", "never"),
            (ESMInfraEntitlement, "xenial", "never"),
            (ESMInfraEntitlement, "bionic", None),
            (ESMInfraEntitlement, "focal", None),
            (ESMAppsEntitlement, "trusty", None),
            (ESMAppsEntitlement, "xenial", "never"),
            (ESMAppsEntitlement, "bionic", None),
            (ESMAppsEntitlement, "focal", None),
        ),
    )
    @mock.patch("uaclient.entitlements.esm.util.get_platform_info")
    def test_esm_infra_repo_pin_priority_never_on_trusty(
        self, m_get_platform_info, esm_class, series, repo_pin_priority
    ):
        """Repository pinning priority for ESMInfra will be 'never' on trusty.

        A pin priority of 'never' means we setup and advertize ESM Infra
        packages without allowing them to be installed until someone attaches
        the machine to Ubuntu Advantage. This is only done for ESM Infra
        on Trusty. We won't want/need to advertize ESM packages on Xenial or
        later. Since we don't advertize ESM Apps on any series,
        repo_pin_priority is None on all series.
        """
        m_get_platform_info.return_value = {"series": series}
        inst = esm_class({})
        assert repo_pin_priority == inst.repo_pin_priority


class TestESMDisableAptAuthOnly:
    @pytest.mark.parametrize(
        "esm_class, series, disable_apt_auth_only",
        (
            (ESMInfraEntitlement, "trusty", True),
            (ESMInfraEntitlement, "xenial", True),
            (ESMInfraEntitlement, "bionic", False),
            (ESMInfraEntitlement, "focal", False),
            (ESMAppsEntitlement, "trusty", False),
            (ESMAppsEntitlement, "xenial", True),
            (ESMAppsEntitlement, "bionic", False),
            (ESMAppsEntitlement, "focal", False),
        ),
    )
    @mock.patch("uaclient.entitlements.esm.util.get_platform_info")
    def test_esm_infra_disable_apt_auth_only_is_true_on_trusty(
        self, m_get_platform_info, esm_class, series, disable_apt_auth_only
    ):
        m_get_platform_info.return_value = {"series": series}
        inst = esm_class({})
        assert disable_apt_auth_only is inst.disable_apt_auth_only


class TestESMInfraEntitlementEnable:
    def test_enable_configures_apt_sources_and_auth_files(self, entitlement):
        """When entitled, configure apt repo auth token, pinning and url."""
        patched_packages = ["a", "b"]
        original_exists = os.path.exists

        def fake_exists(path):
            prefs_path = "/etc/apt/preferences.d/ubuntu-{}".format(
                entitlement.name
            )
            if path == prefs_path:
                return True
            if path in (apt.APT_METHOD_HTTPS_FILE, apt.CA_CERTIFICATES_FILE):
                return True
            return original_exists(path)

        with contextlib.ExitStack() as stack:
            m_add_apt = stack.enter_context(
                mock.patch("uaclient.apt.add_auth_apt_repo")
            )
            m_add_pinning = stack.enter_context(
                mock.patch("uaclient.apt.add_ppa_pinning")
            )
            m_subp = stack.enter_context(
                mock.patch("uaclient.util.subp", return_value=("", ""))
            )
            m_can_enable = stack.enter_context(
                mock.patch.object(entitlement, "can_enable")
            )
            stack.enter_context(
                mock.patch(M_GETPLATFORM, return_value={"series": "trusty"})
            )
            stack.enter_context(
                mock.patch(
                    M_REPOPATH + "os.path.exists", side_effect=fake_exists
                )
            )
            m_unlink = stack.enter_context(
                mock.patch("uaclient.apt.os.unlink")
            )
            # Note that this patch uses a PropertyMock and happens on the
            # entitlement's type because packages is a property
            m_packages = mock.PropertyMock(return_value=patched_packages)
            stack.enter_context(
                mock.patch.object(type(entitlement), "packages", m_packages)
            )

            m_can_enable.return_value = True

            assert True is entitlement.enable()

        add_apt_calls = [
            mock.call(
                "/etc/apt/sources.list.d/ubuntu-{}.list".format(
                    entitlement.name
                ),
                "http://{}".format(entitlement.name.upper()),
                "{}-token".format(entitlement.name),
                ["trusty"],
                entitlement.repo_key_file,
            )
        ]
        install_cmd = mock.call(
            ["apt-get", "install", "--assume-yes"] + patched_packages,
            capture=True,
            retry_sleeps=apt.APT_RETRIES,
            env={},
        )

        subp_calls = [
            mock.call(
                ["apt-get", "update"],
                capture=True,
                retry_sleeps=apt.APT_RETRIES,
                env={},
            ),
            install_cmd,
        ]

        assert [mock.call(silent=mock.ANY)] == m_can_enable.call_args_list
        assert add_apt_calls == m_add_apt.call_args_list
        assert 0 == m_add_pinning.call_count
        assert subp_calls == m_subp.call_args_list
        if entitlement.name == "esm-infra":  # Remove "never" apt pref pin
            unlink_calls = [
                mock.call(
                    "/etc/apt/preferences.d/ubuntu-{}".format(entitlement.name)
                )
            ]
        else:
            unlink_calls = []  # esm-apps doesn't write an apt pref file
        assert unlink_calls == m_unlink.call_args_list

    def test_enable_cleans_up_apt_sources_and_auth_files_on_error(
        self, entitlement, caplog_text
    ):
        """When setup_apt_config fails, cleanup any apt artifacts."""
        original_exists = os.path.exists

        def fake_exists(path):
            prefs_path = "/etc/apt/preferences.d/ubuntu-{}".format(
                entitlement.name
            )
            if path == prefs_path:
                return True
            if path in (apt.APT_METHOD_HTTPS_FILE, apt.CA_CERTIFICATES_FILE):
                return True
            return original_exists(path)

        def fake_subp(cmd, capture=None, retry_sleeps=None, env={}):
            if cmd == ["apt-get", "update"]:
                raise util.ProcessExecutionError(
                    "Failure", stderr="Could not get lock /var/lib/dpkg/lock"
                )
            return "", ""

        with contextlib.ExitStack() as stack:
            m_add_apt = stack.enter_context(
                mock.patch("uaclient.apt.add_auth_apt_repo")
            )
            m_add_pinning = stack.enter_context(
                mock.patch("uaclient.apt.add_ppa_pinning")
            )
            m_subp = stack.enter_context(
                mock.patch("uaclient.util.subp", side_effect=fake_subp)
            )
            m_can_enable = stack.enter_context(
                mock.patch.object(entitlement, "can_enable")
            )
            m_remove_apt_config = stack.enter_context(
                mock.patch.object(entitlement, "remove_apt_config")
            )
            stack.enter_context(
                mock.patch(M_GETPLATFORM, return_value={"series": "trusty"})
            )
            stack.enter_context(
                mock.patch(
                    M_REPOPATH + "os.path.exists", side_effect=fake_exists
                )
            )
            m_unlink = stack.enter_context(
                mock.patch("uaclient.apt.os.unlink")
            )

            m_can_enable.return_value = True

            with pytest.raises(exceptions.UserFacingError) as excinfo:
                entitlement.enable()

        add_apt_calls = [
            mock.call(
                "/etc/apt/sources.list.d/ubuntu-{}.list".format(
                    entitlement.name
                ),
                "http://{}".format(entitlement.name.upper()),
                "{}-token".format(entitlement.name),
                ["trusty"],
                entitlement.repo_key_file,
            )
        ]
        subp_calls = [
            mock.call(
                ["apt-get", "update"],
                capture=True,
                retry_sleeps=apt.APT_RETRIES,
                env={},
            )
        ]

        error_msg = "APT update failed. Another process is running APT."
        assert error_msg == excinfo.value.msg
        assert [mock.call(silent=mock.ANY)] == m_can_enable.call_args_list
        assert add_apt_calls == m_add_apt.call_args_list
        assert 0 == m_add_pinning.call_count
        assert subp_calls == m_subp.call_args_list
        if entitlement.name == "esm-infra":
            # Enable esm-infra trusty removes apt preferences pin 'never' file
            unlink_calls = [
                mock.call(
                    "/etc/apt/preferences.d/ubuntu-{}".format(entitlement.name)
                )
            ]
        else:
            unlink_calls = []  # esm-apps there is no apt pref file to remove
        assert unlink_calls == m_unlink.call_args_list
        assert [
            mock.call(run_apt_update=False)
        ] == m_remove_apt_config.call_args_list


class TestESMEntitlementDisable:
    @pytest.mark.parametrize("silent", [False, True])
    @mock.patch("uaclient.util.get_platform_info")
    @mock.patch(M_PATH + "can_disable", return_value=False)
    def test_disable_returns_false_on_can_disable_false_and_does_nothing(
        self, m_can_disable, m_platform_info, silent
    ):
        """When can_disable is false disable returns false and noops."""
        entitlement = ESMInfraEntitlement({})

        with mock.patch("uaclient.apt.remove_auth_apt_repo") as m_remove_apt:
            assert False is entitlement.disable(silent)
        assert [mock.call(silent)] == m_can_disable.call_args_list
        assert 0 == m_remove_apt.call_count

    @mock.patch(
        "uaclient.util.get_platform_info", return_value={"series": "trusty"}
    )
    def test_disable_on_can_disable_true_removes_apt_config(
        self, _m_platform_info, entitlement, tmpdir
    ):
        """When can_disable, disable removes apt configuration"""

        with mock.patch.object(entitlement, "can_disable", return_value=True):
            with mock.patch.object(
                entitlement, "remove_apt_config"
            ) as m_remove_apt_config:
                assert entitlement.disable(True)
        assert [mock.call()] == m_remove_apt_config.call_args_list
