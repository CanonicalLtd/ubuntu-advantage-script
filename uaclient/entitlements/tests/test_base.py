"""Tests related to uaclient.entitlement.base module."""
import logging
import mock

import pytest

from uaclient import config
from uaclient.entitlements import base
from uaclient import status
from uaclient import util
from uaclient.status import ContractStatus

try:
    from typing import Dict, Optional, Tuple  # noqa
except ImportError:
    pass


class ConcreteTestEntitlement(base.UAEntitlement):

    name = "testconcreteentitlement"
    title = "Test Concrete Entitlement"
    description = "Entitlement for testing"

    def __init__(
        self,
        cfg=None,
        disable=None,
        enable=None,
        applicability_status=None,
        application_status=None,
        allow_beta=False,
    ):
        super().__init__(cfg, allow_beta=allow_beta)
        self._disable = disable
        self._enable = enable
        self._applicability_status = applicability_status
        self._application_status = application_status

    def disable(self):
        self._application_status = (
            status.ApplicationStatus.DISABLED,
            "disable() called",
        )
        return self._disable

    def enable(self, silent_if_inapplicable: bool = False):
        return self._enable

    def applicability_status(self):
        return self._applicability_status

    def application_status(self):
        return self._application_status


@pytest.fixture
def concrete_entitlement_factory(tmpdir):
    def factory(
        *,
        entitled: bool,
        applicability_status: "Tuple[status.ApplicabilityStatus, str]" = None,
        application_status: "Tuple[status.ApplicationStatus, str]" = None,
        feature_overrides: "Optional[Dict[str, str]]" = None,
        allow_beta: bool = False
    ) -> ConcreteTestEntitlement:
        cfg = config.UAConfig(cfg={"data_dir": tmpdir.strpath})
        machineToken = {
            "machineToken": "blah",
            "machineTokenInfo": {
                "contractInfo": {
                    "resourceEntitlements": [
                        {
                            "type": "testconcreteentitlement",
                            "entitled": entitled,
                        }
                    ]
                }
            },
        }
        cfg.write_cache("machine-token", machineToken)

        if feature_overrides:
            cfg.cfg.update({"features": feature_overrides})

        return ConcreteTestEntitlement(
            cfg,
            applicability_status=applicability_status,
            application_status=application_status,
            allow_beta=allow_beta,
        )

    return factory


class TestUaEntitlement:
    def test_entitlement_abstract_class(self):
        """UAEntitlement is abstract requiring concrete methods."""
        with pytest.raises(TypeError) as excinfo:
            base.UAEntitlement()
        expected_msg = (
            "Can't instantiate abstract class UAEntitlement with abstract"
            " methods application_status, description, disable, enable, name,"
            " title"
        )
        assert expected_msg == str(excinfo.value)

    def test_init_default_sets_up_uaconfig(self):
        """UAEntitlement sets up a uaconfig instance upon init."""
        entitlement = ConcreteTestEntitlement()
        assert "/var/lib/ubuntu-advantage" == entitlement.cfg.data_dir

    def test_init_accepts_a_uaconfig(self):
        """An instance of UAConfig can be passed to UAEntitlement."""
        cfg = config.UAConfig(cfg={"data_dir": "/some/path"})
        entitlement = ConcreteTestEntitlement(cfg)
        assert "/some/path" == entitlement.cfg.data_dir

    def test_can_disable_false_on_entitlement_inactive(
        self, capsys, concrete_entitlement_factory
    ):
        """When  status is INACTIVE, can_disable returns False."""
        entitlement = concrete_entitlement_factory(
            entitled=True,
            application_status=(status.ApplicationStatus.DISABLED, ""),
        )

        assert not entitlement.can_disable()

        expected_stdout = (
            "Test Concrete Entitlement is not currently enabled\n"
            "See: sudo ua status\n"
        )
        stdout, _ = capsys.readouterr()
        assert expected_stdout == stdout

    def test_can_disable_true_on_entitlement_active(
        self, capsys, concrete_entitlement_factory
    ):
        """When entitlement is ENABLED, can_disable returns True."""
        entitlement = concrete_entitlement_factory(
            entitled=True,
            application_status=(status.ApplicationStatus.ENABLED, ""),
        )

        assert entitlement.can_disable()

        stdout, _ = capsys.readouterr()
        assert "" == stdout

    @pytest.mark.parametrize("silent", (True, False, None))
    def test_can_enable_false_on_unentitled(
        self, capsys, concrete_entitlement_factory, silent
    ):
        """When entitlement contract is not enabled, can_enable is False."""

        entitlement = concrete_entitlement_factory(entitled=False)

        kwargs = {}
        if silent is not None:
            kwargs["silent"] = silent
        assert not entitlement.can_enable(**kwargs)

        expected_stdout = (
            "This subscription is not entitled to Test Concrete Entitlement\n"
            "For more information see: https://ubuntu.com/advantage.\n"
        )
        if silent:
            expected_stdout = ""
        stdout, _ = capsys.readouterr()
        assert expected_stdout == stdout

    @pytest.mark.parametrize("caplog_text", [logging.DEBUG], indirect=True)
    @mock.patch("uaclient.contract.request_updated_contract")
    def test_can_enable_updates_expired_contract(
        self,
        m_request_updated_contract,
        caplog_text,
        capsys,
        concrete_entitlement_factory,
    ):
        """When entitlement contract is not enabled, can_enable is False."""

        ent = concrete_entitlement_factory(entitled=False)

        with mock.patch.object(ent, "is_access_expired", return_value=True):
            assert not ent.can_enable()

        assert [
            mock.call(ent.cfg)
        ] == m_request_updated_contract.call_args_list
        assert (
            "Updating contract on service 'testconcreteentitlement' expiry"
            in caplog_text()
        )

    @pytest.mark.parametrize("silent", (True, False, None))
    def test_can_enable_false_on_entitlement_active(
        self, capsys, concrete_entitlement_factory, silent
    ):
        """When entitlement is ENABLED, can_enable returns False."""
        application_status = status.ApplicationStatus.ENABLED
        entitlement = concrete_entitlement_factory(
            entitled=True, application_status=(application_status, "")
        )

        kwargs = {}
        if silent is not None:
            kwargs["silent"] = silent
        assert not entitlement.can_enable(**kwargs)

        expected_stdout = (
            "Test Concrete Entitlement is already enabled.\n"
            "See: sudo ua status\n"
        )
        if silent:
            expected_stdout = ""
        stdout, _ = capsys.readouterr()
        assert expected_stdout == stdout

    @pytest.mark.parametrize("silent", (True, False, None))
    def test_can_enable_false_on_entitlement_inapplicable(
        self, capsys, concrete_entitlement_factory, silent
    ):
        """When entitlement is INAPPLICABLE, can_enable returns False."""
        entitlement = concrete_entitlement_factory(
            entitled=True,
            applicability_status=(
                status.ApplicabilityStatus.INAPPLICABLE,
                "msg",
            ),
            application_status=(status.ApplicationStatus.DISABLED, ""),
        )

        kwargs = {}
        if silent is not None:
            kwargs["silent"] = silent
        assert not entitlement.can_enable(**kwargs)

        expected_stdout = "msg\n"
        if silent:
            expected_stdout = ""
        stdout, _ = capsys.readouterr()
        assert expected_stdout == stdout

    @pytest.mark.parametrize("silent", (True, False, None))
    def test_can_enable_true_on_entitlement_inactive(
        self, capsys, concrete_entitlement_factory, silent
    ):
        """When an entitlement is applicable and disabled, we can_enable"""
        entitlement = concrete_entitlement_factory(
            entitled=True,
            applicability_status=(status.ApplicabilityStatus.APPLICABLE, ""),
            application_status=(status.ApplicationStatus.DISABLED, ""),
        )

        kwargs = {}
        if silent is not None:
            kwargs["silent"] = silent
        assert entitlement.can_enable(**kwargs)

        stdout, _ = capsys.readouterr()
        assert "" == stdout

    @pytest.mark.parametrize("is_beta", (True, False))
    @pytest.mark.parametrize("allow_beta", (True, False))
    @pytest.mark.parametrize("allow_beta_cfg", (True, False))
    def test_can_enable_on_beta_service(
        self, allow_beta_cfg, allow_beta, is_beta, concrete_entitlement_factory
    ):

        feature_overrides = {"allow_beta": allow_beta_cfg}
        entitlement = concrete_entitlement_factory(
            entitled=True,
            applicability_status=(status.ApplicabilityStatus.APPLICABLE, ""),
            application_status=(status.ApplicationStatus.DISABLED, ""),
            feature_overrides=feature_overrides,
            allow_beta=allow_beta,
        )
        entitlement.is_beta = is_beta
        can_enable = entitlement.can_enable()

        if not is_beta or allow_beta or allow_beta_cfg:
            assert can_enable
        else:
            assert not can_enable

    def test_contract_status_entitled(self, concrete_entitlement_factory):
        """The contract_status returns ENTITLED when entitlement enabled."""
        entitlement = concrete_entitlement_factory(entitled=True)
        assert ContractStatus.ENTITLED == entitlement.contract_status()

    def test_contract_status_unentitled(self, concrete_entitlement_factory):
        """The contract_status returns NONE when entitlement is unentitled."""
        entitlement = concrete_entitlement_factory(entitled=False)
        assert ContractStatus.UNENTITLED == entitlement.contract_status()

    @pytest.mark.parametrize(
        "orig_access,delta",
        (({}, {}), ({}, {"entitlement": {"entitled": False}})),
    )
    def test_process_contract_deltas_does_nothing_on_empty_orig_access(
        self, concrete_entitlement_factory, orig_access, delta
    ):
        """When orig_acccess dict is empty perform no work."""
        entitlement = concrete_entitlement_factory(
            entitled=True,
            applicability_status=(status.ApplicabilityStatus.APPLICABLE, ""),
            application_status=(status.ApplicationStatus.DISABLED, ""),
        )
        with mock.patch.object(entitlement, "can_disable") as m_can_disable:
            entitlement.process_contract_deltas(orig_access, delta)
        assert 0 == m_can_disable.call_count

    @pytest.mark.parametrize(
        "block_disable_on_enable,assume_yes",
        ((True, True), (False, False), (True, False), (False, True)),
    )
    @mock.patch("uaclient.util.is_config_value_true")
    @mock.patch("uaclient.util.prompt_for_confirmation")
    def test_can_enable_when_incompatible_service_found(
        self,
        m_prompt,
        m_is_config_value_true,
        block_disable_on_enable,
        assume_yes,
        concrete_entitlement_factory,
    ):
        import uaclient.entitlements as ent

        m_prompt.return_value = assume_yes
        m_is_config_value_true.return_value = block_disable_on_enable
        base_ent = concrete_entitlement_factory(
            entitled=True,
            applicability_status=(status.ApplicabilityStatus.APPLICABLE, ""),
            application_status=(status.ApplicationStatus.DISABLED, ""),
        )
        base_ent._incompatible_services = ["test"]

        m_entitlement_cls = mock.MagicMock()
        m_entitlement_obj = m_entitlement_cls.return_value
        m_entitlement_obj.application_status.return_value = [
            status.ApplicationStatus.ENABLED,
            "",
        ]
        type(m_entitlement_obj).title = mock.PropertyMock(return_value="test")

        with mock.patch.object(
            base_ent, "is_access_expired", return_value=False
        ):
            with mock.patch.object(
                ent, "ENTITLEMENT_CLASS_BY_NAME", {"test": m_entitlement_cls}
            ):
                ret = base_ent.can_enable()

        expected_prompt_call = 0 if block_disable_on_enable else 1
        expected_ret = False
        if assume_yes and not block_disable_on_enable:
            expected_ret = True
        expected_disable_call = 1 if expected_ret else 0

        assert ret == expected_ret
        assert m_prompt.call_count == expected_prompt_call
        assert m_is_config_value_true.call_count == 1
        assert m_entitlement_obj.disable.call_count == expected_disable_call

    @pytest.mark.parametrize(
        "orig_access,delta",
        (
            ({"entitlement": {"entitled": True}}, {}),  # no deltas
            (
                {"entitlement": {"entitled": False}},
                {"entitlement": {"entitled": True}},
            ),  # transition to entitled
            (
                {"entitlement": {"entitled": False}},
                {
                    "entitlement": {
                        "entitled": False,  # overridden True by series trusty
                        "series": {"trusty": {"entitled": True}},
                    }
                },
            ),
        ),
    )
    @mock.patch(
        "uaclient.util.get_platform_info", return_value={"series": "trusty"}
    )
    def test_process_contract_deltas_does_nothing_when_delta_remains_entitled(
        self, m_platform_info, concrete_entitlement_factory, orig_access, delta
    ):
        """If deltas do not represent transition to unentitled, do nothing."""
        entitlement = concrete_entitlement_factory(
            entitled=True,
            applicability_status=(status.ApplicabilityStatus.APPLICABLE, ""),
            application_status=(status.ApplicationStatus.DISABLED, ""),
        )
        entitlement.process_contract_deltas(orig_access, delta)
        assert (
            status.ApplicationStatus.DISABLED,
            mock.ANY,
        ) == entitlement.application_status()

    @pytest.mark.parametrize(
        "orig_access,delta",
        (
            (
                {
                    "entitlement": {"entitled": True}
                },  # Full entitlement dropped
                {"entitlement": {"entitled": util.DROPPED_KEY}},
            ),
            (
                {"entitlement": {"entitled": True}},
                {"entitlement": {"entitled": False}},
            ),  # transition to unentitled
        ),
    )
    def test_process_contract_deltas_clean_cache_on_inactive_unentitled(
        self, concrete_entitlement_factory, orig_access, delta, caplog_text
    ):
        """Only clear cache when deltas transition inactive to unentitled."""
        entitlement = concrete_entitlement_factory(
            entitled=True,
            application_status=(status.ApplicationStatus.DISABLED, ""),
        )
        entitlement.process_contract_deltas(orig_access, delta)
        # If an entitlement is disabled, we don't need to tell the user
        # anything about it becoming unentitled
        # (FIXME: Something on bionic means that DEBUG log lines are being
        # picked up by caplog_text(), so work around that here)
        assert [] == [
            line for line in caplog_text().splitlines() if "DEBUG" not in line
        ]

    @pytest.mark.parametrize(
        "orig_access,delta",
        (
            (
                {
                    "entitlement": {"entitled": True}
                },  # Full entitlement dropped
                {"entitlement": {"entitled": util.DROPPED_KEY}},
            ),
            (
                {"entitlement": {"entitled": True}},
                {"entitlement": {"entitled": False}},
            ),  # transition to unentitled
        ),
    )
    def test_process_contract_deltas_disable_on_active_unentitled(
        self, concrete_entitlement_factory, orig_access, delta
    ):
        """Disable when deltas transition from active to unentitled."""
        entitlement = concrete_entitlement_factory(
            entitled=True,
            application_status=(status.ApplicationStatus.ENABLED, ""),
        )
        entitlement.process_contract_deltas(orig_access, delta)
        assert (
            status.ApplicationStatus.DISABLED,
            mock.ANY,
        ) == entitlement.application_status()

    @pytest.mark.parametrize(
        "orig_access,delta",
        (
            (
                {
                    "resourceToken": "test",
                    "entitlement": {
                        "entitled": True,
                        "obligations": {"enableByDefault": False},
                    },
                },
                {
                    "entitlement": {
                        "entitled": True,
                        "obligations": {"enableByDefault": True},
                    }
                },
            ),
        ),
    )
    def test_process_contract_deltas_enable_beta_if_enabled_by_default_turned(
        self, concrete_entitlement_factory, orig_access, delta
    ):
        """Disable when deltas transition from active to unentitled."""
        entitlement = concrete_entitlement_factory(
            entitled=True,
            applicability_status=(status.ApplicabilityStatus.APPLICABLE, ""),
            application_status=(status.ApplicationStatus.DISABLED, ""),
        )
        entitlement.is_beta = True
        assert not entitlement.allow_beta
        with mock.patch.object(entitlement, "enable") as m_enable:
            entitlement.process_contract_deltas(
                orig_access, delta, allow_enable=True
            )
            assert 1 == m_enable.call_count

        assert entitlement.allow_beta


class TestUaEntitlementUserFacingStatus:
    def test_inapplicable_when_not_applicable(
        self, concrete_entitlement_factory
    ):
        msg = "inapplicable for very good reasons"
        entitlement = concrete_entitlement_factory(
            entitled=True,
            applicability_status=(
                status.ApplicabilityStatus.INAPPLICABLE,
                msg,
            ),
        )

        user_facing_status, details = entitlement.user_facing_status()
        assert status.UserFacingStatus.INAPPLICABLE == user_facing_status
        assert msg == details

    def test_unavailable_when_applicable_but_not_entitled(
        self, concrete_entitlement_factory
    ):

        entitlement = concrete_entitlement_factory(
            entitled=False,
            applicability_status=(status.ApplicabilityStatus.APPLICABLE, ""),
        )

        user_facing_status, details = entitlement.user_facing_status()
        assert status.UserFacingStatus.UNAVAILABLE == user_facing_status
        expected_details = "{} is not entitled".format(entitlement.title)
        assert expected_details == details

    def test_unavailable_when_applicable_but_no_entitlement_cfg(
        self, concrete_entitlement_factory
    ):

        entitlement = concrete_entitlement_factory(
            entitled=False,
            applicability_status=(status.ApplicabilityStatus.APPLICABLE, ""),
        )
        entitlement.cfg._entitlements = {}

        user_facing_status, details = entitlement.user_facing_status()
        assert status.UserFacingStatus.UNAVAILABLE == user_facing_status
        expected_details = "{} is not entitled".format(entitlement.title)
        assert expected_details == details

    @pytest.mark.parametrize(
        "application_status,expected_uf_status",
        (
            (status.ApplicationStatus.ENABLED, status.UserFacingStatus.ACTIVE),
            (
                status.ApplicationStatus.DISABLED,
                status.UserFacingStatus.INACTIVE,
            ),
        ),
    )
    def test_application_status_used_if_not_inapplicable(
        self,
        concrete_entitlement_factory,
        application_status,
        expected_uf_status,
    ):
        msg = "application status details"
        entitlement = concrete_entitlement_factory(
            entitled=True,
            applicability_status=(status.ApplicabilityStatus.APPLICABLE, ""),
            application_status=(application_status, msg),
        )

        user_facing_status, details = entitlement.user_facing_status()
        assert expected_uf_status == user_facing_status
        assert msg == details
