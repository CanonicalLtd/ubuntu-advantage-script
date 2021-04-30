"""Tests related to uaclient.entitlement.__init__ module."""
import mock
import pytest

from uaclient import entitlements


class TestValidServices:
    @pytest.mark.parametrize("allow_beta", ((True), (False)))
    @pytest.mark.parametrize("is_beta", ((True), (False)))
    @mock.patch("uaclient.entitlements.is_config_value_true")
    def test_valid_services(self, m_is_config_value, is_beta, allow_beta):
        m_is_config_value.return_value = allow_beta
        m_cls_1 = mock.MagicMock()
        type(m_cls_1).is_beta = mock.PropertyMock(return_value=False)

        m_cls_2 = mock.MagicMock()
        type(m_cls_2).is_beta = mock.PropertyMock(return_value=is_beta)
        ents_dict = {"ent1": m_cls_1, "ent2": m_cls_2}

        with mock.patch.object(
            entitlements, "ENTITLEMENT_CLASS_BY_NAME", ents_dict
        ):
            expected_services = ["ent1"]
            if allow_beta or not is_beta:
                expected_services.append("ent2")

            assert expected_services == entitlements.valid_services()
