import mock
import pytest
import textwrap

from uaclient.cli import action_disable, main
from uaclient import entitlements
from uaclient import exceptions
from uaclient import status


ALL_SERVICE_MSG = "\n".join(
    textwrap.wrap(
        "Try " + ", ".join(entitlements.valid_services(allow_beta=True)) + ".",
        width=80,
        break_long_words=False,
    )
)

HELP_OUTPUT = textwrap.dedent(
    """\
usage: ua disable <service> [<service>] [flags]

Disable an Ubuntu Advantage service.

Arguments:
  service       the name(s) of the Ubuntu Advantage services to disable One
                of: esm-infra, fips, fips-updates, livepatch

Flags:
  -h, --help    show this help message and exit
  --assume-yes  do not prompt for confirmation before performing the disable
"""
)


@mock.patch("uaclient.cli.os.getuid", return_value=0)
class TestDisable:
    def test_disable_help(self, _getuid, capsys):
        with pytest.raises(SystemExit):
            with mock.patch("sys.argv", ["/usr/bin/ua", "disable", "--help"]):
                main()
        out, _err = capsys.readouterr()
        assert HELP_OUTPUT == out

    @pytest.mark.parametrize("service", [["testitlement"], ["ent1", "ent2"]])
    @pytest.mark.parametrize("assume_yes", (True, False))
    @pytest.mark.parametrize(
        "disable_return,return_code", ((True, 0), (False, 1))
    )
    @mock.patch("uaclient.cli.entitlements")
    def test_entitlement_instantiated_and_disabled(
        self,
        m_entitlements,
        _m_getuid,
        disable_return,
        return_code,
        assume_yes,
        service,
        tmpdir,
    ):
        entitlements_cls = []
        entitlements_obj = []
        m_entitlements.ENTITLEMENT_CLASS_BY_NAME = {}
        for entitlement_name in service:
            m_entitlement_cls = mock.Mock()

            m_entitlement = m_entitlement_cls.return_value
            m_entitlement.disable.return_value = disable_return

            m_entitlements.ENTITLEMENT_CLASS_BY_NAME[
                entitlement_name
            ] = m_entitlement_cls

            entitlements_obj.append(m_entitlement)
            entitlements_cls.append(m_entitlement_cls)
        m_cfg = mock.Mock()
        m_cfg.check_lock_info.return_value = (-1, "")
        m_cfg.data_path.return_value = tmpdir.join("lock").strpath

        args_mock = mock.Mock()
        args_mock.service = service
        args_mock.assume_yes = assume_yes

        ret = action_disable(args_mock, m_cfg)

        for m_entitlement_cls in entitlements_cls:
            assert [
                mock.call(m_cfg, assume_yes=assume_yes)
            ] == m_entitlement_cls.call_args_list

        expected_disable_call = mock.call()
        for m_entitlement in entitlements_obj:
            assert [
                expected_disable_call
            ] == m_entitlement.disable.call_args_list

        assert return_code == ret
        assert len(entitlements_cls) == m_cfg.status.call_count

    @pytest.mark.parametrize("assume_yes", (True, False))
    @mock.patch(
        "uaclient.entitlements.is_config_value_true", return_value=False
    )
    def test_entitlements_not_found_disabled_and_enabled(
        self, _m_is_config_value_true, _m_getuid, assume_yes, tmpdir
    ):
        expected_error_tmpl = status.MESSAGE_INVALID_SERVICE_OP_FAILURE_TMPL
        num_calls = 2

        m_ent1_cls = mock.Mock()
        m_ent1_obj = m_ent1_cls.return_value
        m_ent1_obj.disable.return_value = False

        m_ent2_cls = mock.Mock()
        m_ent2_obj = m_ent2_cls.return_value
        m_ent2_obj.disable.return_value = False

        m_ent3_cls = mock.Mock()
        m_ent3_obj = m_ent3_cls.return_value
        m_ent3_obj.disable.return_value = True

        m_ents_dict = {"ent2": m_ent2_cls, "ent3": m_ent3_cls}

        m_cfg = mock.Mock()
        m_cfg.check_lock_info.return_value = (-1, "")
        m_cfg.data_path.return_value = tmpdir.join("lock").strpath
        args_mock = mock.Mock()
        args_mock.service = ["ent1", "ent2", "ent3"]
        args_mock.assume_yes = assume_yes

        with mock.patch.object(
            entitlements, "ENTITLEMENT_CLASS_BY_NAME", m_ents_dict
        ):
            with pytest.raises(exceptions.UserFacingError) as err:
                action_disable(args_mock, m_cfg)

        assert (
            expected_error_tmpl.format(
                operation="disable", name="ent1", service_msg="Try ent2, ent3."
            )
            == err.value.msg
        )

        for m_ent_cls in [m_ent2_cls, m_ent3_cls]:
            assert [
                mock.call(m_cfg, assume_yes=assume_yes)
            ] == m_ent_cls.call_args_list

        expected_disable_call = mock.call()
        for m_ent in [m_ent2_obj, m_ent3_obj]:
            assert [expected_disable_call] == m_ent.disable.call_args_list

        assert 0 == m_ent1_obj.call_count
        assert num_calls == m_cfg.status.call_count

    @pytest.mark.parametrize(
        "uid,expected_error_template",
        [
            (0, status.MESSAGE_INVALID_SERVICE_OP_FAILURE_TMPL),
            (1000, status.MESSAGE_NONROOT_USER),
        ],
    )
    def test_invalid_service_error_message(
        self, m_getuid, uid, expected_error_template, FakeConfig
    ):
        """Check invalid service name results in custom error message."""
        m_getuid.return_value = uid

        cfg = FakeConfig.for_attached_machine()
        with pytest.raises(exceptions.UserFacingError) as err:
            args = mock.MagicMock()
            args.service = ["bogus"]
            action_disable(args, cfg)
        assert (
            expected_error_template.format(
                operation="disable", name="bogus", service_msg=ALL_SERVICE_MSG
            )
            == err.value.msg
        )

    @pytest.mark.parametrize("service", [["bogus"], ["bogus1", "bogus2"]])
    def test_invalid_service_names(self, m_getuid, service, FakeConfig):
        m_getuid.return_value = 0
        expected_error_tmpl = status.MESSAGE_INVALID_SERVICE_OP_FAILURE_TMPL

        cfg = FakeConfig.for_attached_machine()
        with pytest.raises(exceptions.UserFacingError) as err:
            args = mock.MagicMock()
            args.service = service
            action_disable(args, cfg)

        assert (
            expected_error_tmpl.format(
                operation="disable",
                name=", ".join(sorted(service)),
                service_msg=ALL_SERVICE_MSG,
            )
            == err.value.msg
        )

    @pytest.mark.parametrize(
        "uid,expected_error_template",
        [
            (0, status.MESSAGE_ENABLE_FAILURE_UNATTACHED_TMPL),
            (1000, status.MESSAGE_NONROOT_USER),
        ],
    )
    def test_unattached_error_message(
        self, m_getuid, uid, expected_error_template, FakeConfig
    ):
        """Check that root user gets unattached message."""
        m_getuid.return_value = uid

        cfg = FakeConfig()
        with pytest.raises(exceptions.UserFacingError) as err:
            args = mock.MagicMock()
            args.service = ["esm-infra"]
            action_disable(args, cfg)
        assert (
            expected_error_template.format(name="esm-infra") == err.value.msg
        )

    @mock.patch("uaclient.cli.util.subp")
    def test_lock_file_exists(self, m_subp, m_getuid, FakeConfig):
        """Check inability to disable if operation in progress holds lock."""

        cfg = FakeConfig().for_attached_machine()
        with open(cfg.data_path("lock"), "w") as stream:
            stream.write("123:ua enable")
        with pytest.raises(exceptions.LockHeldError) as err:
            args = mock.MagicMock()
            args.service = ["esm-infra"]
            action_disable(args, cfg)
        assert [mock.call(["ps", "123"])] == m_subp.call_args_list
        assert (
            "Unable to perform: ua disable.\n"
            "Operation in progress: ua enable (pid:123)"
        ) == err.value.msg
