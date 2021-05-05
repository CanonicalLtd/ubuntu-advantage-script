import io
import json
import mock
import os
import socket
import sys
import textwrap

import pytest

from uaclient import util

from uaclient.cli import action_status, main
from uaclient import status

M_PATH = "uaclient.cli."


RESPONSE_LIVEPATCH_AVAILABLE = [{"name": "livepatch", "available": True}]
UNATTACHED_STATUS = """\
SERVICE       AVAILABLE  DESCRIPTION
livepatch     yes        Canonical Livepatch service

This machine is not attached to a UA subscription.
See https://ubuntu.com/advantage
"""

ATTACHED_STATUS = """\
SERVICE       ENTITLED  STATUS    DESCRIPTION
cc-eal        no        {dash}         Common Criteria EAL2 Provisioning\
 Packages
cis           no        {dash}         Center for Internet Security Audit Tools
esm-apps      no        {dash}         UA Apps: Extended Security Maintenance\
 (ESM)
esm-infra     no        {dash}         UA Infra: Extended Security Maintenance\
 (ESM)
fips          no        {dash}         NIST-certified FIPS modules
fips-updates  no        {dash}         Uncertified security updates to FIPS\
 modules
livepatch     no        {dash}         Canonical Livepatch service
{notices}
Enable services with: ua enable <service>

                Account: test_account
           Subscription: test_contract
            Valid until: n/a
Technical support level: n/a
"""

# Omit beta services from status
ATTACHED_STATUS_NOBETA = """\
SERVICE       ENTITLED  STATUS    DESCRIPTION
esm-apps      no        {dash}         UA Apps: Extended Security Maintenance\
 (ESM)
esm-infra     no        {dash}         UA Infra: Extended Security Maintenance\
 (ESM)
fips          no        {dash}         NIST-certified FIPS modules
fips-updates  no        {dash}         Uncertified security updates to FIPS\
 modules
livepatch     no        {dash}         Canonical Livepatch service
{notices}
Enable services with: ua enable <service>

                Account: test_account
           Subscription: test_contract
            Valid until: n/a
Technical support level: n/a
"""

BETA_SVC_NAMES = ["cc-eal", "cis"]

SERVICES_JSON_ALL = [
    {
        "description": "Common Criteria EAL2 Provisioning Packages",
        "description_override": None,
        "entitled": "no",
        "name": "cc-eal",
        "status": "—",
        "statusDetails": "",
    },
    {
        "description": "Center for Internet Security Audit Tools",
        "description_override": None,
        "entitled": "no",
        "name": "cis",
        "status": "—",
        "statusDetails": "",
    },
    {
        "description": "UA Apps: Extended Security Maintenance (ESM)",
        "description_override": None,
        "entitled": "no",
        "name": "esm-apps",
        "status": "—",
        "statusDetails": "",
    },
    {
        "description": "UA Infra: Extended Security Maintenance (ESM)",
        "description_override": None,
        "entitled": "no",
        "name": "esm-infra",
        "status": "—",
        "statusDetails": "",
    },
    {
        "description": "NIST-certified FIPS modules",
        "description_override": None,
        "entitled": "no",
        "name": "fips",
        "status": "—",
        "statusDetails": "",
    },
    {
        "description": "Uncertified security updates to FIPS modules",
        "description_override": None,
        "entitled": "no",
        "name": "fips-updates",
        "status": "—",
        "statusDetails": "",
    },
    {
        "description": "Canonical Livepatch service",
        "description_override": None,
        "entitled": "no",
        "name": "livepatch",
        "status": "—",
        "statusDetails": "",
    },
]

HELP_OUTPUT = textwrap.dedent(
    """\
usage: ua status [flags]

Report current status of Ubuntu Advantage services on system.

This shows whether this machine is attached to an Ubuntu Advantage
support contract. When attached, the report includes the specific
support contract details including contract name, expiry dates, and the
status of each service on this system.

The attached status output has four columns:

* SERVICE: name of the service
* ENTITLED: whether the contract to which this machine is attached
  entitles use of this service. Possible values are: yes or no
* STATUS: whether the service is enabled on this machine. Possible
  values are: enabled, disabled, n/a (if your contract entitles
  you to the service, but it isn't available for this machine) or — (if
  you aren't entitled to this service)
* DESCRIPTION: a brief description of the service

The unattached status output instead has three columns. SERVICE
and DESCRIPTION are the same as above, and there is the addition
of:

* AVAILABLE: whether this service would be available if this machine
  were attached. The possible values are yes or no.

Flags:
  -h, --help            show this help message and exit
  --wait                Block waiting on ua to complete
  --format {tabular,json}
                        output status in the specified format (default:
                        tabular)
  --all                 Allow the visualization of beta services
"""
)


@mock.patch("uaclient.util.should_reboot", return_value=False)
@mock.patch("uaclient.config.UAConfig.remove_notice")
@mock.patch(
    M_PATH + "contract.get_available_resources",
    return_value=RESPONSE_LIVEPATCH_AVAILABLE,
)
@mock.patch(M_PATH + "os.getuid", return_value=0)
class TestActionStatus:
    def test_status_help(
        self,
        _getuid,
        _get_available_resources,
        _m_should_reboot,
        _m_remove_notice,
        capsys,
    ):
        with pytest.raises(SystemExit):
            with mock.patch("sys.argv", ["/usr/bin/ua", "status", "--help"]):
                main()
        out, _err = capsys.readouterr()
        assert HELP_OUTPUT == out

    @pytest.mark.parametrize("use_all", (True, False))
    @pytest.mark.parametrize(
        "notices,notice_status",
        (
            ([], ""),
            (
                [["a", "adesc"], ["b2", "bdesc"]],
                "\nNOTICES\n a: adesc\nb2: bdesc\n",
            ),
        ),
    )
    def test_attached(
        self,
        m_getuid,
        m_get_avail_resources,
        _m_should_reboot,
        _m_remove_notice,
        notices,
        notice_status,
        use_all,
        capsys,
        FakeConfig,
    ):
        """Check that root and non-root will emit attached status"""
        cfg = FakeConfig.for_attached_machine()
        cfg.write_cache("notices", notices)
        assert 0 == action_status(mock.MagicMock(all=use_all), cfg)
        # capsys already converts colorized non-printable chars to space
        # Strip non-printables from output
        printable_stdout = capsys.readouterr()[0].replace(" " * 17, " " * 8)

        # On older versions of pytest, capsys doesn't set sys.stdout.encoding
        # to something that Python parses as UTF-8 compatible, so we get the
        # ASCII dash; testing for the "wrong" dash here is OK, because we have
        # a specific test that the correct one is used in
        # test_unicode_dash_replacement_when_unprintable
        expected_dash = "-"
        status_tmpl = ATTACHED_STATUS if use_all else ATTACHED_STATUS_NOBETA

        if sys.stdout.encoding and "UTF-8" in sys.stdout.encoding.upper():
            expected_dash = "\u2014"
        assert (
            status_tmpl.format(dash=expected_dash, notices=notice_status)
            == printable_stdout
        )

    def test_unattached(
        self,
        m_getuid,
        m_get_avail_resources,
        _m_should_reboot,
        _m_remove_notice,
        capsys,
        FakeConfig,
    ):
        """Check that unattached status is emitted to console"""
        cfg = FakeConfig()

        assert 0 == action_status(mock.MagicMock(all=False), cfg)
        assert UNATTACHED_STATUS == capsys.readouterr()[0]

    @mock.patch("uaclient.util.subp")
    @mock.patch(M_PATH + "time.sleep")
    def test_wait_blocks_until_lock_released(
        self,
        m_sleep,
        m_subp,
        m_getuid,
        m_get_avail_resources,
        _m_should_reboot,
        _m_remove_notice,
        capsys,
        FakeConfig,
    ):
        """Check that --wait will will block and poll until lock released."""
        cfg = FakeConfig()
        lock_file = cfg.data_path("lock")
        cfg.write_cache("lock", "123:ua auto-attach")

        def fake_sleep(seconds):
            if m_sleep.call_count == 3:
                os.unlink(lock_file)

        m_sleep.side_effect = fake_sleep

        assert 0 == action_status(mock.MagicMock(all=False), cfg)
        assert [mock.call(1)] * 3 == m_sleep.call_args_list
        assert "...\n" + UNATTACHED_STATUS == capsys.readouterr()[0]

    @pytest.mark.parametrize("use_all", (True, False))
    def test_unattached_json(
        self,
        m_getuid,
        m_get_avail_resources,
        _m_should_reboot,
        _m_remove_notice,
        use_all,
        capsys,
        FakeConfig,
    ):
        """Check that unattached status json output is emitted to console"""
        cfg = FakeConfig()

        args = mock.MagicMock(format="json", all=use_all)
        assert 0 == action_status(args, cfg)

        expected = {
            "_doc": (
                "Content provided in json response is currently "
                "considered Experimental and may change"
            ),
            "configStatus": status.UserFacingConfigStatus.INACTIVE.value,
            "configStatusDetails": status.MESSAGE_NO_ACTIVE_OPERATIONS,
            "attached": False,
            "expires": "n/a",
            "notices": [],
            "origin": None,
            "services": [
                {
                    "name": "livepatch",
                    "description": "Canonical Livepatch service",
                    "available": "yes",
                }
            ],
            "techSupportLevel": "n/a",
        }
        assert expected == json.loads(capsys.readouterr()[0])

    @pytest.mark.parametrize("use_all", (True, False))
    def test_attached_json(
        self,
        m_getuid,
        m_get_avail_resources,
        _m_should_reboot,
        _m_remove_notice,
        use_all,
        capsys,
        FakeConfig,
    ):
        """Check that unattached status json output is emitted to console"""
        cfg = FakeConfig.for_attached_machine()

        args = mock.MagicMock(format="json", all=use_all)
        assert 0 == action_status(args, cfg)

        if use_all:
            services = SERVICES_JSON_ALL
        else:
            services = [
                svc
                for svc in SERVICES_JSON_ALL
                if svc["name"] not in BETA_SVC_NAMES
            ]
        expected = {
            "_doc": (
                "Content provided in json response is currently "
                "considered Experimental and may change"
            ),
            "configStatus": status.UserFacingConfigStatus.INACTIVE.value,
            "configStatusDetails": status.MESSAGE_NO_ACTIVE_OPERATIONS,
            "attached": True,
            "expires": "n/a",
            "notices": [],
            "origin": None,
            "services": services,
            "account": "test_account",
            "account-id": "acct-1",
            "subscription": "test_contract",
            "subscription-id": "cid",
            "techSupportLevel": "n/a",
        }
        assert expected == json.loads(capsys.readouterr()[0])

    def test_error_on_connectivity_errors(
        self,
        m_getuid,
        m_get_avail_resources,
        _m_should_reboot,
        _m_remove_notice,
        capsys,
        FakeConfig,
    ):
        """Raise UrlError on connectivity issues"""
        m_get_avail_resources.side_effect = util.UrlError(
            socket.gaierror(-2, "Name or service not known")
        )

        cfg = FakeConfig()

        with pytest.raises(util.UrlError):
            action_status(mock.MagicMock(all=False), cfg)

    @pytest.mark.parametrize(
        "encoding,expected_dash",
        (("utf-8", "\u2014"), ("UTF-8", "\u2014"), ("ascii", "-")),
    )
    def test_unicode_dash_replacement_when_unprintable(
        self,
        _m_getuid,
        _m_get_avail_resources,
        _m_should_reboot,
        _m_remove_notice,
        encoding,
        expected_dash,
        FakeConfig,
    ):
        # This test can't use capsys because it doesn't emulate sys.stdout
        # encoding accurately in older versions of pytest
        underlying_stdout = io.BytesIO()
        fake_stdout = io.TextIOWrapper(underlying_stdout, encoding=encoding)

        with mock.patch("sys.stdout", fake_stdout):
            action_status(
                mock.MagicMock(all=True), FakeConfig.for_attached_machine()
            )

        fake_stdout.flush()  # Make sure all output is in underlying_stdout
        out = underlying_stdout.getvalue().decode(encoding)

        # Colour codes are converted to spaces, so strip them out for
        # comparison
        out = out.replace(" " * 17, " " * 8)

        expected_out = ATTACHED_STATUS.format(dash=expected_dash, notices="")
        assert expected_out == out
