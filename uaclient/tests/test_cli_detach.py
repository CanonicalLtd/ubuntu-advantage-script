import mock
from textwrap import dedent

import pytest

from uaclient.cli import action_detach
from uaclient import exceptions
from uaclient import status
from uaclient.testing.fakes import FakeConfig


def entitlement_cls_mock_factory(can_disable, name=None):
    m_instance = mock.Mock(can_disable=mock.Mock(return_value=can_disable))
    if name:
        m_instance.name = name
    return mock.Mock(return_value=m_instance)


@mock.patch("uaclient.cli.os.getuid")
class TestActionDetach:
    def test_non_root_users_are_rejected(self, m_getuid):
        """Check that a UID != 0 will receive a message and exit non-zero"""
        m_getuid.return_value = 1

        cfg = FakeConfig.for_attached_machine()
        with pytest.raises(exceptions.NonRootUserError):
            action_detach(mock.MagicMock(), cfg)

    def test_unattached_error_message(self, m_getuid):
        """Check that root user gets unattached message."""

        m_getuid.return_value = 0
        cfg = FakeConfig()
        with pytest.raises(exceptions.UnattachedError) as err:
            action_detach(mock.MagicMock(), cfg)
        assert status.MESSAGE_UNATTACHED == err.value.msg

    @mock.patch("uaclient.cli.entitlements")
    def test_entitlements_disabled_if_can_disable(
        self, m_entitlements, m_getuid
    ):
        m_getuid.return_value = 0

        m_entitlements.ENTITLEMENT_CLASSES = [
            entitlement_cls_mock_factory(False),
            entitlement_cls_mock_factory(True),
            entitlement_cls_mock_factory(False),
        ]

        action_detach(mock.MagicMock(), FakeConfig.for_attached_machine())

        # Check that can_disable is called correctly
        for ent_cls in m_entitlements.ENTITLEMENT_CLASSES:
            assert [
                mock.call(silent=True)
            ] == ent_cls.return_value.can_disable.call_args_list

        # Check that disable is only called when can_disable is true
        for undisabled_cls in [
            m_entitlements.ENTITLEMENT_CLASSES[0],
            m_entitlements.ENTITLEMENT_CLASSES[2],
        ]:
            assert 0 == undisabled_cls.return_value.disable.call_count
        disabled_cls = m_entitlements.ENTITLEMENT_CLASSES[1]
        assert [
            mock.call(silent=True)
        ] == disabled_cls.return_value.disable.call_args_list

    @mock.patch("uaclient.cli.entitlements")
    def test_config_cache_deleted(self, m_entitlements, m_getuid):
        m_getuid.return_value = 0
        m_entitlements.ENTITLEMENT_CLASSES = []

        cfg = mock.MagicMock()
        action_detach(mock.MagicMock(), cfg)

        assert [mock.call()] == cfg.delete_cache.call_args_list

    @mock.patch("uaclient.cli.entitlements")
    def test_correct_message_emitted(self, m_entitlements, m_getuid, capsys):
        m_getuid.return_value = 0
        m_entitlements.ENTITLEMENT_CLASSES = []

        action_detach(mock.MagicMock(), mock.MagicMock())

        out, _err = capsys.readouterr()

        assert status.MESSAGE_DETACH_SUCCESS + "\n" == out

    @mock.patch("uaclient.cli.entitlements")
    def test_returns_zero(self, m_entitlements, m_getuid):
        m_getuid.return_value = 0
        m_entitlements.ENTITLEMENT_CLASSES = []

        ret = action_detach(mock.MagicMock(), mock.MagicMock())

        assert 0 == ret

    @pytest.mark.parametrize(
        "classes,expected_message",
        [
            (
                [
                    entitlement_cls_mock_factory(True, name="ent1"),
                    entitlement_cls_mock_factory(False, name="ent2"),
                    entitlement_cls_mock_factory(True, name="ent3"),
                ],
                dedent(
                    """\
                    Detach will disable the following services:
                        ent1
                        ent3"""
                ),
            ),
            (
                [
                    entitlement_cls_mock_factory(True, name="ent1"),
                    entitlement_cls_mock_factory(False, name="ent2"),
                ],
                dedent(
                    """\
                    Detach will disable the following service:
                        ent1"""
                ),
            ),
        ],
    )
    @mock.patch("uaclient.cli.entitlements")
    def test_informational_message_emitted(
        self, m_entitlements, m_getuid, capsys, classes, expected_message
    ):
        m_getuid.return_value = 0
        m_entitlements.ENTITLEMENT_CLASSES = classes
        action_detach(mock.MagicMock(), mock.MagicMock())

        out, _err = capsys.readouterr()

        assert expected_message in out