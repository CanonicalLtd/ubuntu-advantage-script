import datetime
import mock
import os

import pytest

from uaclient.defaults import (
    BASE_ESM_URL,
    BASE_UA_URL,
    CONTRACT_EXPIRY_GRACE_PERIOD_DAYS,
)
from uaclient.status import (
    MESSAGE_ANNOUNCE_ESM,
    MESSAGE_CONTRACT_EXPIRED_APT_NO_PKGS_TMPL,
    MESSAGE_CONTRACT_EXPIRED_APT_PKGS_TMPL,
    MESSAGE_CONTRACT_EXPIRED_GRACE_PERIOD_TMPL,
    MESSAGE_CONTRACT_EXPIRED_SOON_TMPL,
    MESSAGE_DISABLED_MOTD_NO_PKGS_TMPL,
    MESSAGE_DISABLED_APT_PKGS_TMPL,
    MESSAGE_UBUNTU_NO_WARRANTY,
    ApplicationStatus,
)
from uaclient import util

from lib.ua_update_messaging import (
    ContractExpiryStatus,
    ExternalMessage,
    get_contract_expiry_status,
    update_apt_and_motd_messages,
    write_apt_and_motd_templates,
    write_esm_announcement_message,
    _write_esm_service_msg_templates,
)

M_PATH = "lib.ua_update_messaging."


class TestGetContractExpiryStatus:
    @pytest.mark.parametrize(
        "contract_remaining_days,expected_status",
        (
            (21, ContractExpiryStatus.ACTIVE),
            (20, ContractExpiryStatus.ACTIVE_EXPIRED_SOON),
            (-1, ContractExpiryStatus.EXPIRED_GRACE_PERIOD),
            (-20, ContractExpiryStatus.EXPIRED),
        ),
    )
    def test_contract_expiry_status_based_on_remaining_days(
        self, contract_remaining_days, expected_status, FakeConfig
    ):
        """Return a tuple of ContractExpiryStatus and remaining_days"""
        now = datetime.datetime.utcnow()
        expire_date = now + datetime.timedelta(days=contract_remaining_days)
        cfg = FakeConfig.for_attached_machine()
        m_token = cfg.machine_token
        m_token["machineTokenInfo"]["contractInfo"][
            "effectiveTo"
        ] = expire_date.strftime("%Y-%m-%dT%H:%M:%SZ")

        assert (
            expected_status,
            contract_remaining_days,
        ) == get_contract_expiry_status(cfg)


class TestWriteAPTAndMOTDTemplates:
    @pytest.mark.parametrize(
        "is_active_esm,contract_expiry_status,no_warranty",
        (
            (True, ContractExpiryStatus.EXPIRED, True),
            (True, ContractExpiryStatus.NONE, True),
            (True, ContractExpiryStatus.ACTIVE, False),
            (True, ContractExpiryStatus.EXPIRED_GRACE_PERIOD, False),
            (True, ContractExpiryStatus.ACTIVE_EXPIRED_SOON, False),
        ),
    )
    @mock.patch(M_PATH + "entitlements")
    @mock.patch(M_PATH + "_write_esm_service_msg_templates")
    @mock.patch(M_PATH + "util.is_active_esm")
    @mock.patch(M_PATH + "get_contract_expiry_status")
    def test_write_apps_or_infra_services_emits_no_warranty(
        self,
        get_contract_expiry_status,
        util_is_active_esm,
        write_esm_service_templates,
        entitlements,
        is_active_esm,
        contract_expiry_status,
        no_warranty,
        FakeConfig,
    ):
        util_is_active_esm.return_value = is_active_esm
        entitlements.ENTITLEMENT_CLASS_BY_NAME = {
            "esm-apps": mock.MagicMock(),
            "esm-infra": mock.MagicMock(),
        }
        get_contract_expiry_status.return_value = (
            contract_expiry_status,
            -12355,  # unused in this test
        )
        cfg = FakeConfig.for_attached_machine()
        msg_dir = os.path.join(cfg.data_dir, "messages")
        os.makedirs(msg_dir)

        write_apt_and_motd_templates(cfg, "xenial")
        assert [mock.call("xenial")] == util_is_active_esm.call_args_list
        no_warranty_file = os.path.join(msg_dir, "ubuntu-no-warranty")
        if no_warranty:
            assert MESSAGE_UBUNTU_NO_WARRANTY == util.load_file(
                no_warranty_file
            )
        else:
            assert False is os.path.exists(no_warranty_file)

    @pytest.mark.parametrize(
        "series,is_active_esm,contract_days,infra_enabled,"
        "esm_apps_beta,cfg_allow_beta,show_infra,show_apps",
        (
            # Enabled infra, active contract, beta apps: show none
            ("xenial", True, 21, True, True, None, False, False),
            # Not enabled infra, beta apps: show infra msg
            ("xenial", True, -21, False, True, None, True, False),
            # Any *expired contract, infra enabled, beta apps: show infra msg
            ("xenial", True, 20, True, True, None, True, False),
            ("xenial", True, 0, True, True, None, True, False),
            ("xenial", True, -1, True, True, None, True, False),
            ("xenial", True, -21, True, True, None, True, False),
            # Infra enabled, any *expired contract, allow_beta: show infra msg
            ("xenial", True, 20, True, True, True, True, False),
            # Infra enabled, active contract, allow_beta: show apps msg
            ("xenial", True, 21, True, True, True, False, True),
            # Infra enabled, active contract, apps not beta: show apps msg
            ("xenial", True, 21, True, False, None, False, True),
        ),
    )
    @mock.patch(M_PATH + "entitlements")
    @mock.patch(M_PATH + "_write_esm_service_msg_templates")
    @mock.patch(M_PATH + "util.is_active_esm")
    @mock.patch(M_PATH + "get_contract_expiry_status")
    def test_write_apps_or_infra_services_mutually_exclusive(
        self,
        get_contract_expiry_status,
        util_is_active_esm,
        write_esm_service_templates,
        entitlements,
        series,
        is_active_esm,
        contract_days,
        infra_enabled,
        esm_apps_beta,
        cfg_allow_beta,
        show_infra,
        show_apps,
        FakeConfig,
    ):
        """Write Infra or Apps when Apps not-beta service.

        Messaging is mutually exclusive, if Infra templates are emitted, don't
        write Apps.
        """
        get_contract_expiry_status.return_value = (
            ContractExpiryStatus.ACTIVE,
            contract_days,
        )
        if infra_enabled:
            infra_status = ApplicationStatus.ENABLED
        else:
            infra_status = ApplicationStatus.DISABLED
        util_is_active_esm.return_value = is_active_esm
        infra_cls = mock.MagicMock()
        infra_obj = infra_cls.return_value
        infra_obj.application_status.return_value = (infra_status, "")
        type(infra_obj).name = mock.PropertyMock(return_value="esm-infra")
        apps_cls = mock.MagicMock()
        type(apps_cls).is_beta = esm_apps_beta
        apps_obj = apps_cls.return_value
        type(apps_obj).name = mock.PropertyMock(return_value="esm-apps")
        entitlements.ENTITLEMENT_CLASS_BY_NAME = {
            "esm-apps": apps_cls,
            "esm-infra": infra_cls,
        }
        cfg = FakeConfig.for_attached_machine()
        if cfg_allow_beta:
            cfg.override_features({"allow_beta": cfg_allow_beta})
        write_calls = [
            mock.call(
                cfg,
                mock.ANY,
                ContractExpiryStatus.ACTIVE,
                contract_days,
                ExternalMessage.APT_PRE_INVOKE_INFRA_PKGS.value,
                ExternalMessage.APT_PRE_INVOKE_INFRA_NO_PKGS.value,
                ExternalMessage.MOTD_INFRA_PKGS.value,
                ExternalMessage.MOTD_INFRA_NO_PKGS.value,
                remove_template_files=not show_infra,
            ),
            mock.call(
                cfg,
                mock.ANY,
                ContractExpiryStatus.ACTIVE,
                contract_days,
                ExternalMessage.APT_PRE_INVOKE_APPS_PKGS.value,
                ExternalMessage.APT_PRE_INVOKE_APPS_NO_PKGS.value,
                ExternalMessage.MOTD_APPS_PKGS.value,
                ExternalMessage.MOTD_APPS_NO_PKGS.value,
                remove_template_files=not show_apps,
            ),
        ]
        write_apt_and_motd_templates(cfg, series)
        assert [mock.call(cfg)] == get_contract_expiry_status.call_args_list
        assert write_calls == write_esm_service_templates.call_args_list


class Test_WriteESMServiceAPTMsgTemplates:
    @pytest.mark.parametrize(
        "service_name,contract_expiry,expect_messages,platform_info,"
        "eol_release,url",
        (
            (
                "esm-apps",
                ContractExpiryStatus.ACTIVE,
                True,
                {"series": "xenial", "release": "16.04"},
                "",
                BASE_ESM_URL,
            ),
            (
                "esm-infra",
                ContractExpiryStatus.ACTIVE,
                True,
                {"series": "xenial", "release": "16.04"},
                "for Ubuntu 16.04 ",
                "https://ubuntu.com/16-04",
            ),
            (
                "esm-apps",
                ContractExpiryStatus.ACTIVE,
                True,
                {"series": "xenial", "release": "16.04"},
                "",
                BASE_ESM_URL,
            ),
            (
                "esm-apps",
                ContractExpiryStatus.EXPIRED,
                False,
                {"series": "xenial", "release": "16.04"},
                "",
                BASE_ESM_URL,
            ),
        ),
    )
    @mock.patch(M_PATH + "util.get_platform_info")
    @mock.patch(M_PATH + "util.is_active_esm", return_value=True)
    @mock.patch(
        M_PATH + "entitlements.repo.RepoEntitlement.application_status"
    )
    def test_apt_templates_written_for_disabled_services(
        self,
        app_status,
        util_is_active_esm,
        get_platform_info,
        service_name,
        contract_expiry,
        expect_messages,
        platform_info,
        eol_release,
        url,
        FakeConfig,
        tmpdir,
    ):
        """Disabled service messages are omitted if contract expired.

        This represents customer chosen disabling of service on an attached
        machine. So, they've chosen to disable expired services.
        """
        if service_name == "esm-infra":
            title = "UA Infra: ESM"
            pkg_count_var = "{ESM_INFRA_PKG_COUNT}"
            pkg_names_var = "{ESM_INFRA_PACKAGES}"
        else:
            title = "UA Apps: ESM"
            pkg_count_var = "{ESM_APPS_PKG_COUNT}"
            pkg_names_var = "{ESM_APPS_PACKAGES}"
        get_platform_info.return_value = platform_info
        m_entitlement_cls = mock.MagicMock()
        m_ent_obj = m_entitlement_cls.return_value
        disabled_status = ApplicationStatus.DISABLED, ""
        m_ent_obj.application_status.return_value = disabled_status
        type(m_ent_obj).name = mock.PropertyMock(return_value=service_name)
        type(m_ent_obj).title = mock.PropertyMock(return_value=title)
        pkgs_file = tmpdir.join("pkgs-msg")
        no_pkgs_file = tmpdir.join("no-pkgs-msg")
        motd_pkgs_file = tmpdir.join("motd-pkgs-msg")
        motd_no_pkgs_file = tmpdir.join("motd-no-pkgs-msg")
        _write_esm_service_msg_templates(
            FakeConfig.for_attached_machine(),
            m_ent_obj,
            contract_expiry,
            21,
            pkgs_file.strpath,
            no_pkgs_file.strpath,
            motd_pkgs_file.strpath,
            motd_no_pkgs_file.strpath,
        )
        if expect_messages:
            assert (
                MESSAGE_DISABLED_APT_PKGS_TMPL.format(
                    title=title,
                    pkg_num=pkg_count_var,
                    pkg_names=pkg_names_var,
                    eol_release=eol_release,
                    url=url,
                )
                == pkgs_file.read()
            )
            assert (
                MESSAGE_DISABLED_MOTD_NO_PKGS_TMPL.format(title=title, url=url)
                == no_pkgs_file.read()
            )
        else:
            assert False is os.path.exists(pkgs_file.strpath)
            assert False is os.path.exists(no_pkgs_file.strpath)

    @pytest.mark.parametrize(
        "contract_status, remaining_days, is_active_esm, platform_info",
        (
            (
                ContractExpiryStatus.ACTIVE,
                21,
                True,
                {"series": "xenial", "releaes": "16.04"},
            ),
            (
                ContractExpiryStatus.ACTIVE_EXPIRED_SOON,
                10,
                True,
                {"series": "xenial", "releaes": "16.04"},
            ),
            (
                ContractExpiryStatus.EXPIRED_GRACE_PERIOD,
                -5,
                True,
                {"series": "xenial", "releaes": "16.04"},
            ),
            (
                ContractExpiryStatus.EXPIRED,
                -20,
                True,
                {"series": "xenial", "releaes": "16.04"},
            ),
            (
                ContractExpiryStatus.EXPIRED,
                -20,
                False,
                {"series": "xenial", "releaes": "16.04"},
            ),
        ),
    )
    @mock.patch(M_PATH + "util.get_platform_info")
    @mock.patch(M_PATH + "util.is_active_esm")
    @mock.patch(
        M_PATH + "entitlements.repo.RepoEntitlement.application_status"
    )
    def test_apt_templates_written_for_enabled_services_by_contract_status(
        self,
        app_status,
        util_is_active_esm,
        get_platform_info,
        contract_status,
        remaining_days,
        is_active_esm,
        platform_info,
        FakeConfig,
        tmpdir,
    ):
        get_platform_info.return_value = platform_info
        util_is_active_esm.return_value = is_active_esm
        m_entitlement_cls = mock.MagicMock()
        m_ent_obj = m_entitlement_cls.return_value
        disabled_status = ApplicationStatus.ENABLED, ""
        m_ent_obj.application_status.return_value = disabled_status
        type(m_ent_obj).name = mock.PropertyMock(return_value="esm-apps")
        type(m_ent_obj).title = mock.PropertyMock(return_value="UA Apps: ESM")
        pkgs_tmpl = tmpdir.join("pkgs-msg.tmpl")
        no_pkgs_tmpl = tmpdir.join("no-pkgs-msg.tmpl")
        motd_pkgs_tmpl = tmpdir.join("motd-pkgs-msg.tmpl")
        motd_no_pkgs_tmpl = tmpdir.join("motd-no-pkgs-msg.tmpl")
        pkgs_tmpl.write("oldcache")
        no_pkgs_tmpl.write("oldcache")
        motd_pkgs_tmpl.write("oldcache")
        motd_no_pkgs_tmpl.write("oldcache")
        no_pkgs_msg_file = no_pkgs_tmpl.strpath.replace(".tmpl", "")
        pkgs_msg_file = pkgs_tmpl.strpath.replace(".tmpl", "")
        util.write_file(no_pkgs_msg_file, "oldcache")
        util.write_file(pkgs_msg_file, "oldcache")

        now = datetime.datetime.utcnow()
        expire_date = now + datetime.timedelta(days=remaining_days)
        cfg = FakeConfig.for_attached_machine()
        m_token = cfg.machine_token
        m_token["machineTokenInfo"]["contractInfo"][
            "effectiveTo"
        ] = expire_date.strftime("%Y-%m-%dT%H:%M:%SZ")

        _write_esm_service_msg_templates(
            cfg,
            m_ent_obj,
            contract_status,
            remaining_days,
            pkgs_tmpl.strpath,
            no_pkgs_tmpl.strpath,
            motd_pkgs_tmpl.strpath,
            motd_no_pkgs_tmpl.strpath,
        )
        if contract_status == ContractExpiryStatus.ACTIVE:
            # Old messages removed on ACTIVE status
            assert False is os.path.exists(pkgs_tmpl.strpath)
            assert False is os.path.exists(no_pkgs_tmpl.strpath)
            assert False is os.path.exists(motd_pkgs_tmpl.strpath)
            assert False is os.path.exists(motd_no_pkgs_tmpl.strpath)
            assert False is os.path.exists(pkgs_msg_file)
            assert False is os.path.exists(no_pkgs_msg_file)
        elif contract_status == ContractExpiryStatus.ACTIVE_EXPIRED_SOON:
            pkgs_msg = MESSAGE_CONTRACT_EXPIRED_SOON_TMPL.format(
                title="UA Apps: ESM",
                remaining_days=remaining_days,
                url=BASE_UA_URL,
            )
            assert pkgs_msg == pkgs_tmpl.read()
            assert pkgs_msg == no_pkgs_tmpl.read()
        elif contract_status == ContractExpiryStatus.EXPIRED_GRACE_PERIOD:
            pkgs_msg = MESSAGE_CONTRACT_EXPIRED_GRACE_PERIOD_TMPL.format(
                title="UA Apps: ESM",
                expired_date=cfg.contract_expiry_datetime.strftime("%d %b %Y"),
                remaining_days=remaining_days
                + CONTRACT_EXPIRY_GRACE_PERIOD_DAYS,
                url=BASE_UA_URL,
            )
            assert pkgs_msg == pkgs_tmpl.read()
            assert pkgs_msg == no_pkgs_tmpl.read()
        elif contract_status == ContractExpiryStatus.EXPIRED:
            pkgs_msg = MESSAGE_CONTRACT_EXPIRED_APT_PKGS_TMPL.format(
                pkg_num="{ESM_APPS_PKG_COUNT}",
                pkg_names="{ESM_APPS_PACKAGES}",
                title="UA Apps: ESM",
                name="esm-apps",
                url=BASE_UA_URL,
            )
            no_pkgs_msg = MESSAGE_CONTRACT_EXPIRED_APT_NO_PKGS_TMPL.format(
                title="UA Apps: ESM", url=BASE_UA_URL
            )
            assert pkgs_msg == pkgs_tmpl.read()
            assert no_pkgs_msg == no_pkgs_tmpl.read()


class TestWriteESMAnnouncementMessage:
    @pytest.mark.parametrize(
        "series,is_beta,cfg_allow_beta,apps_enabled,expected",
        (
            # No ESM announcement when trusty
            ("trusty", False, True, False, None),
            # ESMApps.is_beta == True no Announcement
            ("xenial", True, None, False, None),
            # Once release begins ESM and ESMApps.is_beta is false announce
            ("xenial", False, None, False, "\n" + MESSAGE_ANNOUNCE_ESM),
            # allow_beta uaclient.config overrides is_beta and days_until_esm
            ("xenial", True, True, False, "\n" + MESSAGE_ANNOUNCE_ESM),
            # when esm-apps already enabled don't show
            ("xenial", False, True, True, None),
            ("bionic", False, None, False, "\n" + MESSAGE_ANNOUNCE_ESM),
            ("focal", False, None, False, "\n" + MESSAGE_ANNOUNCE_ESM),
        ),
    )
    @mock.patch(
        M_PATH + "entitlements.repo.RepoEntitlement.application_status"
    )
    @mock.patch(M_PATH + "entitlements")
    @mock.patch(M_PATH + "util.get_platform_info")
    def test_message_based_on_beta_status_and_count_until_active_esm(
        self,
        get_platform_info,
        entitlements,
        esm_application_status,
        series,
        is_beta,
        cfg_allow_beta,
        apps_enabled,
        expected,
        FakeConfig,
    ):
        get_platform_info.return_value = {"series": series}

        cfg = FakeConfig.for_attached_machine()
        msg_dir = os.path.join(cfg.data_dir, "messages")
        os.makedirs(msg_dir)
        esm_news_path = os.path.join(msg_dir, "motd-esm-announce")

        if cfg_allow_beta:
            cfg.override_features({"allow_beta": cfg_allow_beta})

        m_entitlement_cls = mock.MagicMock()
        type(m_entitlement_cls).is_beta = is_beta
        m_ent_obj = m_entitlement_cls.return_value
        if apps_enabled:
            status_return = ApplicationStatus.ENABLED, ""
        else:
            status_return = ApplicationStatus.DISABLED, ""
        m_ent_obj.application_status.return_value = status_return

        type(m_entitlement_cls).is_beta = is_beta
        entitlements.ENTITLEMENT_CLASS_BY_NAME = {
            "esm-apps": m_entitlement_cls
        }
        write_esm_announcement_message(cfg, series)
        if expected is None:
            assert False is os.path.exists(esm_news_path)
        else:
            assert expected == util.load_file(esm_news_path)


class TestUpdateAPTandMOTDMessages:
    @pytest.mark.parametrize(
        "series,is_lts,esm_active,cfg_allow_beta",
        (
            ("xenial", True, True, True),
            ("bionic", True, False, True),
            ("bionic", True, False, None),
            ("groovy", False, False, None),
        ),
    )
    @mock.patch(M_PATH + "util.is_lts")
    @mock.patch(M_PATH + "util.is_active_esm")
    @mock.patch(M_PATH + "write_apt_and_motd_templates")
    @mock.patch(M_PATH + "write_esm_announcement_message")
    @mock.patch(M_PATH + "util.subp")
    @mock.patch(M_PATH + "util.get_platform_info")
    def test_motd_and_apt_templates_written_separately(
        self,
        get_platform_info,
        subp,
        write_esm_announcement_message,
        write_apt_and_motd_templates,
        is_active_esm,
        util_is_lts,
        series,
        is_lts,
        esm_active,
        cfg_allow_beta,
        FakeConfig,
    ):
        """Update message templates for LTS releases with esm active.

        Assert cleanup of cached template and rendered message files when
        non-LTS release.

        Allow config allow_beta overrides.
        """
        get_platform_info.return_value = {"series": series}
        util_is_lts.return_value = is_lts
        is_active_esm.return_value = esm_active
        cfg = FakeConfig.for_attached_machine()
        if cfg_allow_beta:
            cfg.override_features({"allow_beta": cfg_allow_beta})
        msg_dir = os.path.join(cfg.data_dir, "messages")
        if not is_lts:
            # setup old msg files to assert they are removed
            os.makedirs(msg_dir)
            for msg_enum in ExternalMessage:
                msg_path = os.path.join(msg_dir, msg_enum.value)
                util.write_file(msg_path, "old")
                util.write_file(msg_path.replace(".tmpl", ""), "old")

        update_apt_and_motd_messages(cfg)
        os.path.exists(os.path.join(cfg.data_dir, "messages"))

        if is_lts:
            write_apt_calls = [mock.call(cfg, series)]
            esm_announce_calls = [mock.call(cfg, series)]
            subp_calls = [
                mock.call(
                    [
                        "/usr/lib/ubuntu-advantage/apt-esm-hook",
                        "process-templates",
                    ]
                )
            ]
        else:
            write_apt_calls = esm_announce_calls = []
            subp_calls = []
            # Cached msg templates removed on non-LTS
            for msg_enum in ExternalMessage:
                msg_path = os.path.join(msg_dir, msg_enum.value)
                assert False is os.path.exists(msg_path)
                assert False is os.path.exists(msg_path.replace(".tmpl", ""))
        assert (
            esm_announce_calls == write_esm_announcement_message.call_args_list
        )
        assert write_apt_calls == write_apt_and_motd_templates.call_args_list
        assert subp_calls == subp.call_args_list
