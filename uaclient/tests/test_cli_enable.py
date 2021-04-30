import contextlib
import io
import mock
import textwrap

import pytest

from uaclient.cli import _perform_enable, action_enable, main
from uaclient import entitlements
from uaclient import exceptions
from uaclient import status

HELP_OUTPUT = textwrap.dedent(
    """\
usage: ua enable <service> [<service>] [flags]

Enable an Ubuntu Advantage service.

Arguments:
  service       the name(s) of the Ubuntu Advantage services to enable. One
                of: esm-infra, fips, fips-updates, livepatch

Flags:
  -h, --help    show this help message and exit
  --assume-yes  do not prompt for confirmation before performing the enable
  --beta        allow beta service to be enabled
"""
)


@mock.patch("uaclient.cli.os.getuid")
@mock.patch("uaclient.contract.request_updated_contract")
class TestActionEnable:
    def test_enable_help(self, _getuid, _request_updated_contract, capsys):
        with pytest.raises(SystemExit):
            with mock.patch("sys.argv", ["/usr/bin/ua", "enable", "--help"]):
                main()
        out, _err = capsys.readouterr()
        assert HELP_OUTPUT == out

    def test_non_root_users_are_rejected(
        self, _request_updated_contract, getuid, FakeConfig
    ):
        """Check that a UID != 0 will receive a message and exit non-zero"""
        getuid.return_value = 1

        cfg = FakeConfig.for_attached_machine()
        with pytest.raises(exceptions.NonRootUserError):
            action_enable(mock.MagicMock(), cfg)

    @mock.patch("uaclient.cli.util.subp")
    def test_lock_file_exists(
        self, m_subp, _request_updated_contract, getuid, FakeConfig
    ):
        """Check inability to enable if operation holds lock file."""
        getuid.return_value = 0
        cfg = FakeConfig.for_attached_machine()
        cfg.write_cache("lock", "123:ua disable")
        with pytest.raises(exceptions.LockHeldError) as err:
            action_enable(mock.MagicMock(), cfg)
        assert [mock.call(["ps", "123"])] == m_subp.call_args_list
        assert (
            "Unable to perform: ua enable.\n"
            "Operation in progress: ua disable (pid:123)"
        ) == err.value.msg

    @pytest.mark.parametrize(
        "uid,expected_error_template",
        [
            (0, status.MESSAGE_ENABLE_FAILURE_UNATTACHED_TMPL),
            (1000, status.MESSAGE_NONROOT_USER),
        ],
    )
    def test_unattached_error_message(
        self,
        _request_updated_contract,
        m_getuid,
        uid,
        expected_error_template,
        FakeConfig,
    ):
        """Check that root user gets unattached message."""

        m_getuid.return_value = uid
        cfg = FakeConfig()
        with pytest.raises(exceptions.UserFacingError) as err:
            args = mock.MagicMock()
            args.service = ["esm-infra"]
            action_enable(args, cfg)
        assert (
            expected_error_template.format(name="esm-infra") == err.value.msg
        )

    @pytest.mark.parametrize(
        "uid,expected_error_template",
        [
            (0, status.MESSAGE_INVALID_SERVICE_OP_FAILURE_TMPL),
            (1000, status.MESSAGE_NONROOT_USER),
        ],
    )
    def test_invalid_service_error_message(
        self,
        _request_updated_contract,
        m_getuid,
        uid,
        expected_error_template,
        FakeConfig,
    ):
        """Check invalid service name results in custom error message."""

        m_getuid.return_value = uid
        cfg = FakeConfig.for_attached_machine()
        with pytest.raises(exceptions.UserFacingError) as err:
            args = mock.MagicMock()
            args.service = ["bogus"]
            action_enable(args, cfg)
        service_msg = "\n".join(
            textwrap.wrap(
                (
                    "Try "
                    + ", ".join(entitlements.valid_services(allow_beta=True))
                    + "."
                ),
                width=80,
                break_long_words=False,
            )
        )
        assert (
            expected_error_template.format(
                operation="enable", name="bogus", service_msg=service_msg
            )
            == err.value.msg
        )

    @pytest.mark.parametrize("assume_yes", (True, False))
    @mock.patch("uaclient.contract.get_available_resources", return_value={})
    @mock.patch("uaclient.entitlements.valid_services")
    def test_assume_yes_passed_to_service_init(
        self,
        m_valid_services,
        _m_get_available_resources,
        m_request_updated_contract,
        m_getuid,
        assume_yes,
        FakeConfig,
    ):
        """assume-yes parameter is passed to entitlement instantiation."""
        m_getuid.return_value = 0

        m_entitlement_cls = mock.MagicMock()
        m_ents_dict = {"testitlement": m_entitlement_cls}
        m_valid_services.return_value = list(m_ents_dict.keys())
        m_entitlement_obj = m_entitlement_cls.return_value
        m_entitlement_obj.enable.return_value = True

        cfg = FakeConfig.for_attached_machine()
        args = mock.MagicMock()
        args.service = ["testitlement"]
        args.assume_yes = assume_yes
        args.beta = False

        with mock.patch.object(
            entitlements, "ENTITLEMENT_CLASS_BY_NAME", m_ents_dict
        ):
            action_enable(args, cfg)

        assert [
            mock.call(cfg, assume_yes=assume_yes, allow_beta=False)
        ] == m_entitlement_cls.call_args_list

    @pytest.mark.parametrize("silent_if_inapplicable", (True, False, None))
    @mock.patch("uaclient.contract.get_available_resources", return_value={})
    def test_entitlements_not_found_disabled_and_enabled(
        self,
        _m_get_available_resources,
        _m_request_updated_contract,
        m_getuid,
        silent_if_inapplicable,
        FakeConfig,
    ):
        m_getuid.return_value = 0
        expected_error_tmpl = status.MESSAGE_INVALID_SERVICE_OP_FAILURE_TMPL

        m_ent1_cls = mock.Mock()
        m_ent1_obj = m_ent1_cls.return_value
        m_ent1_obj.enable.return_value = False

        m_ent2_cls = mock.Mock()
        m_ent2_is_beta = mock.PropertyMock(return_value=True)
        type(m_ent2_cls).is_beta = m_ent2_is_beta
        m_ent2_obj = m_ent2_cls.return_value
        m_ent2_obj.enable.return_value = False

        m_ent3_cls = mock.Mock()
        m_ent3_is_beta = mock.PropertyMock(return_value=False)
        type(m_ent3_cls).is_beta = m_ent3_is_beta
        m_ent3_obj = m_ent3_cls.return_value
        m_ent3_obj.enable.return_value = True

        m_ents_dict = {"ent2": m_ent2_cls, "ent3": m_ent3_cls}

        cfg = FakeConfig.for_attached_machine()
        assume_yes = False
        args_mock = mock.Mock()
        args_mock.service = ["ent1", "ent2", "ent3"]
        args_mock.assume_yes = assume_yes
        args_mock.beta = False

        expected_msg = "One moment, checking your subscription first\n"

        with mock.patch.object(
            entitlements, "ENTITLEMENT_CLASS_BY_NAME", m_ents_dict
        ):
            with pytest.raises(exceptions.UserFacingError) as err:
                fake_stdout = io.StringIO()
                with contextlib.redirect_stdout(fake_stdout):
                    action_enable(args_mock, cfg)

            assert (
                expected_error_tmpl.format(
                    operation="enable",
                    name="ent1, ent2",
                    service_msg=(
                        "Try "
                        + ", ".join(
                            entitlements.valid_services(allow_beta=False)
                        )
                        + "."
                    ),
                )
                == err.value.msg
            )
            assert expected_msg == fake_stdout.getvalue()

        for m_ent_cls in [m_ent2_cls, m_ent3_cls]:
            assert [
                mock.call(cfg, assume_yes=assume_yes, allow_beta=False)
            ] == m_ent_cls.call_args_list

        expected_enable_call = mock.call(silent_if_inapplicable=False)
        for m_ent in [m_ent2_obj, m_ent3_obj]:
            assert [expected_enable_call] == m_ent.enable.call_args_list

        assert 0 == m_ent1_obj.call_count

    @pytest.mark.parametrize("beta_flag", ((False), (True)))
    @pytest.mark.parametrize("silent_if_inapplicable", (True, False, None))
    @mock.patch("uaclient.contract.get_available_resources", return_value={})
    @mock.patch(
        "uaclient.entitlements.is_config_value_true", return_value=False
    )
    def test_entitlements_not_found_and_beta(
        self,
        _m_is_config_value_true,
        _m_get_available_resources,
        _m_request_updated_contract,
        m_getuid,
        silent_if_inapplicable,
        beta_flag,
        FakeConfig,
    ):
        m_getuid.return_value = 0
        expected_error_tmpl = status.MESSAGE_INVALID_SERVICE_OP_FAILURE_TMPL

        m_ent1_cls = mock.Mock()
        m_ent1_obj = m_ent1_cls.return_value
        m_ent1_obj.enable.return_value = False

        m_ent2_cls = mock.Mock()
        m_ent2_is_beta = mock.PropertyMock(return_value=True)
        type(m_ent2_cls)._is_beta = m_ent2_is_beta
        m_ent2_obj = m_ent2_cls.return_value
        m_ent2_obj.enable.return_value = False

        m_ent3_cls = mock.Mock()
        m_ent3_is_beta = mock.PropertyMock(return_value=False)
        type(m_ent3_cls)._is_beta = m_ent3_is_beta
        m_ent3_obj = m_ent3_cls.return_value
        m_ent3_obj.enable.return_value = True

        m_ents_dict = {"ent2": m_ent2_cls, "ent3": m_ent3_cls}

        cfg = FakeConfig.for_attached_machine()
        assume_yes = False
        args_mock = mock.Mock()
        args_mock.service = ["ent1", "ent2", "ent3"]
        args_mock.assume_yes = assume_yes
        args_mock.beta = beta_flag

        expected_msg = "One moment, checking your subscription first\n"
        not_found_name = "ent1"
        mock_ent_list = [m_ent3_cls]
        mock_obj_list = [m_ent3_obj]

        with mock.patch.object(
            entitlements, "ENTITLEMENT_CLASS_BY_NAME", m_ents_dict
        ):
            service_names = entitlements.valid_services(allow_beta=beta_flag)
            if not beta_flag:
                not_found_name += ", ent2"
                ent_str = "Try " + ", ".join(service_names) + "."
            else:
                ent_str = "Try " + ", ".join(service_names) + "."
                mock_ent_list.append(m_ent2_cls)
                mock_obj_list.append(m_ent3_obj)
            service_msg = "\n".join(
                textwrap.wrap(ent_str, width=80, break_long_words=False)
            )

            with pytest.raises(exceptions.UserFacingError) as err:
                fake_stdout = io.StringIO()
                with contextlib.redirect_stdout(fake_stdout):
                    action_enable(args_mock, cfg)

            assert (
                expected_error_tmpl.format(
                    operation="enable",
                    name=not_found_name,
                    service_msg=service_msg,
                )
                == err.value.msg
            )
            assert expected_msg == fake_stdout.getvalue()

        for m_ent_cls in mock_ent_list:
            assert [
                mock.call(cfg, assume_yes=assume_yes, allow_beta=beta_flag)
            ] == m_ent_cls.call_args_list

        expected_enable_call = mock.call(silent_if_inapplicable=False)
        for m_ent in mock_obj_list:
            assert [expected_enable_call] == m_ent.enable.call_args_list

        assert 0 == m_ent1_obj.call_count

    @pytest.mark.parametrize(
        "service, beta",
        ((["bogus"], False), (["bogus"], True), (["bogus1", "bogus2"], False)),
    )
    def test_invalid_service_names(
        self, _m_request_updated_contract, m_getuid, service, beta, FakeConfig
    ):
        m_getuid.return_value = 0
        expected_error_tmpl = status.MESSAGE_INVALID_SERVICE_OP_FAILURE_TMPL
        expected_msg = "One moment, checking your subscription first\n"

        cfg = FakeConfig.for_attached_machine()
        with pytest.raises(exceptions.UserFacingError) as err:
            fake_stdout = io.StringIO()
            with contextlib.redirect_stdout(fake_stdout):
                args = mock.MagicMock()
                args.service = service
                args.beta = beta
                action_enable(args, cfg)

        assert expected_msg == fake_stdout.getvalue()

        service_names = entitlements.valid_services(allow_beta=beta)
        if beta:
            ent_str = "Try " + ", ".join(service_names) + "."
        else:
            ent_str = "Try " + ", ".join(service_names) + "."
        service_msg = "\n".join(
            textwrap.wrap(ent_str, width=80, break_long_words=False)
        )
        assert (
            expected_error_tmpl.format(
                operation="enable",
                name=", ".join(sorted(service)),
                service_msg=service_msg,
            )
            == err.value.msg
        )


class TestPerformEnable:
    @mock.patch("uaclient.entitlements.valid_services")
    def test_missing_entitlement_raises_keyerror(self, m_valid_services):
        """We raise a KeyError on missing entitlements

        (This isn't a problem because any callers of _perform_enable should
        already have rejected invalid names.)
        """
        m_valid_services.return_value = "entitlement"
        with pytest.raises(KeyError):
            _perform_enable("entitlement", mock.Mock())

    @pytest.mark.parametrize("allow_beta", ((True), (False)))
    @pytest.mark.parametrize("silent_if_inapplicable", (True, False, None))
    @mock.patch("uaclient.contract.get_available_resources", return_value={})
    @mock.patch(
        "uaclient.entitlements.is_config_value_true", return_value=False
    )
    def test_entitlement_instantiated_and_enabled(
        self,
        _m_is_config_value_true,
        _m_get_available_resources,
        silent_if_inapplicable,
        allow_beta,
    ):
        m_entitlement_cls = mock.Mock()
        m_cfg = mock.Mock()

        m_ents_dict = {"testitlement": m_entitlement_cls}

        kwargs = {"allow_beta": allow_beta}
        if silent_if_inapplicable is not None:
            kwargs["silent_if_inapplicable"] = silent_if_inapplicable

        with mock.patch.object(
            entitlements, "ENTITLEMENT_CLASS_BY_NAME", m_ents_dict
        ):
            ret = _perform_enable("testitlement", m_cfg, **kwargs)

        assert [
            mock.call(m_cfg, assume_yes=False, allow_beta=allow_beta)
        ] == m_entitlement_cls.call_args_list

        m_entitlement = m_entitlement_cls.return_value
        if silent_if_inapplicable:
            expected_enable_call = mock.call(silent_if_inapplicable=True)
        else:
            expected_enable_call = mock.call(silent_if_inapplicable=False)
        assert [expected_enable_call] == m_entitlement.enable.call_args_list
        assert ret == m_entitlement.enable.return_value

        assert 1 == m_cfg.status.call_count
