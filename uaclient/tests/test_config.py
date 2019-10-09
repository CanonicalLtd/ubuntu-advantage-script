import copy
import datetime
import itertools
import json
import os
import stat

import mock
import pytest

from uaclient import entitlements, exceptions, status
from uaclient.config import (
    DataPath,
    DEFAULT_STATUS,
    PRIVATE_SUBDIR,
    UAConfig,
    parse_config,
)
from uaclient.entitlements import (
    ENTITLEMENT_CLASSES,
    ENTITLEMENT_CLASS_BY_NAME,
)
from uaclient.testing.fakes import FakeConfig
from uaclient.status import ContractStatus, UserFacingStatus


KNOWN_DATA_PATHS = (("machine-token", "machine-token.json"),)
M_PATH = "uaclient.entitlements."


RESP_ALL_RESOURCES_AVAILABLE = [
    {"name": name, "available": True} for name in ENTITLEMENT_CLASS_BY_NAME
]
RESP_ONLY_FIPS_RESOURCE_AVAILABLE = [
    {"name": name, "available": name == "fips"}
    for name in ENTITLEMENT_CLASS_BY_NAME
]


class TestEntitlements:
    def test_entitlements_property_keyed_by_entitlement_name(self, tmpdir):
        """Return machine_token resourceEntitlements, keyed by name."""
        cfg = UAConfig({"data_dir": tmpdir.strpath})
        token = {
            "machineTokenInfo": {
                "contractInfo": {
                    "resourceEntitlements": [
                        {"type": "entitlement1", "entitled": True},
                        {"type": "entitlement2", "entitled": True},
                    ]
                }
            }
        }
        cfg.write_cache("machine-token", token)
        expected = {
            "entitlement1": {
                "entitlement": {"entitled": True, "type": "entitlement1"}
            },
            "entitlement2": {
                "entitlement": {"entitled": True, "type": "entitlement2"}
            },
        }
        assert expected == cfg.entitlements

    def test_entitlements_use_machine_access_when_present(self, tmpdir):
        """Return specific machine-access info if present."""
        cfg = UAConfig({"data_dir": tmpdir.strpath})
        token = {
            "machineTokenInfo": {
                "contractInfo": {
                    "resourceEntitlements": [
                        {"type": "entitlement1", "entitled": True},
                        {"type": "entitlement2", "entitled": True},
                    ]
                }
            }
        }
        cfg.write_cache("machine-token", token)
        cfg.write_cache(
            "machine-access-entitlement1",
            {
                "entitlement": {
                    "type": "entitlement1",
                    "entitled": True,
                    "more": "data",
                }
            },
        )
        expected = {
            "entitlement1": {
                "entitlement": {
                    "entitled": True,
                    "type": "entitlement1",
                    "more": "data",
                }
            },
            "entitlement2": {
                "entitlement": {"entitled": True, "type": "entitlement2"}
            },
        }
        assert expected == cfg.entitlements


class TestAccounts:
    def test_accounts_returns_empty_list_when_no_cached_account_value(
        self, tmpdir
    ):
        """Config.accounts property returns an empty list when no cache."""
        cfg = UAConfig({"data_dir": tmpdir.strpath})

        assert [] == cfg.accounts

    def test_accounts_extracts_accounts_key_from_machine_token_cache(
        self, tmpdir
    ):
        """Use machine_token cached accountInfo when no accounts cache."""
        cfg = UAConfig({"data_dir": tmpdir.strpath})
        accountInfo = {"id": "1", "name": "accountname"}

        cfg.write_cache(
            "machine-token", {"machineTokenInfo": {"accountInfo": accountInfo}}
        )

        assert [accountInfo] == cfg.accounts


class TestDataPath:
    def test_data_path_returns_data_dir_path_without_key(self):
        """The data_path method returns the data_dir when key is absent."""
        cfg = UAConfig({"data_dir": "/my/dir"})
        assert "/my/dir/{}".format(PRIVATE_SUBDIR) == cfg.data_path()

    @pytest.mark.parametrize("key,path_basename", KNOWN_DATA_PATHS)
    def test_data_path_returns_file_path_with_defined_data_paths(
        self, key, path_basename
    ):
        """When key is defined in Config.data_paths return data_path value."""
        cfg = UAConfig({"data_dir": "/my/dir"})
        private_path = "/my/dir/{}/{}".format(PRIVATE_SUBDIR, path_basename)
        assert private_path == cfg.data_path(key=key)

    @pytest.mark.parametrize(
        "key,path_basename", (("notHere", "notHere"), ("anything", "anything"))
    )
    def test_data_path_returns_file_path_with_undefined_data_paths(
        self, key, path_basename
    ):
        """When key is not in Config.data_paths the key is used to data_dir"""
        cfg = UAConfig({"data_dir": "/my/d"})
        assert "/my/d/{}/{}".format(PRIVATE_SUBDIR, key) == cfg.data_path(
            key=key
        )

    def test_data_path_returns_public_path_for_public_datapath(self):
        cfg = UAConfig({"data_dir": "/my/d"})
        cfg.data_paths["test_path"] = DataPath("test_path", False)
        assert "/my/d/test_path" == cfg.data_path("test_path")


class TestWriteCache:
    @pytest.mark.parametrize(
        "key,content",
        (("unknownkey", "content1"), ("another-one", "content2")),
    )
    def test_write_cache_write_key_name_in_data_dir_when_data_path_absent(
        self, tmpdir, key, content
    ):
        """When key is not in data_paths, write content to data_dir/key."""
        cfg = UAConfig({"data_dir": tmpdir.strpath})
        expected_path = tmpdir.join(PRIVATE_SUBDIR, key)

        assert not expected_path.check(), "Found unexpected file {}".format(
            expected_path
        )
        assert None is cfg.write_cache(key, content)
        assert expected_path.check(), "Missing expected file {}".format(
            expected_path
        )
        assert content == cfg.read_cache(key)

    def test_write_cache_creates_secure_private_dir(self, tmpdir):
        """private_dir is created with permission 0o700."""
        cfg = UAConfig({"data_dir": tmpdir.strpath})
        # unknown keys are written to the private dir
        expected_dir = tmpdir.join(PRIVATE_SUBDIR)
        assert None is cfg.write_cache("somekey", "somevalue")
        assert True is os.path.isdir(
            expected_dir.strpath
        ), "Missing expected directory {}".format(expected_dir)
        assert 0o700 == stat.S_IMODE(os.lstat(expected_dir.strpath).st_mode)

    def test_write_cache_creates_dir_when_data_dir_does_not_exist(
        self, tmpdir
    ):
        """When data_dir doesn't exist, create it."""
        tmp_subdir = tmpdir.join("does/not/exist")
        cfg = UAConfig({"data_dir": tmp_subdir.strpath})

        assert False is os.path.isdir(
            tmp_subdir.strpath
        ), "Found unexpected directory {}".format(tmp_subdir)
        assert None is cfg.write_cache("somekey", "someval")
        assert True is os.path.isdir(
            tmp_subdir.strpath
        ), "Missing expected directory {}".format(tmp_subdir)
        assert "someval" == cfg.read_cache("somekey")

    @pytest.mark.parametrize(
        "key,value", (("dictkey", {"1": "v1"}), ("listkey", [1, 2, 3]))
    )
    def test_write_cache_writes_json_string_when_content_not_a_string(
        self, tmpdir, key, value
    ):
        """When content is not a string, write a json string."""
        cfg = UAConfig({"data_dir": tmpdir.strpath})

        expected_json_content = json.dumps(value)
        assert None is cfg.write_cache(key, value)
        with open(tmpdir.join(PRIVATE_SUBDIR, key).strpath, "r") as stream:
            assert expected_json_content == stream.read()
        assert value == cfg.read_cache(key)

    @pytest.mark.parametrize(
        "datapath,mode",
        ((DataPath("path", False), 0o644), (DataPath("path", True), 0o600)),
    )
    def test_permissions(self, tmpdir, datapath, mode):
        cfg = UAConfig({"data_dir": tmpdir.strpath})
        cfg.data_paths = {"path": datapath}
        cfg.write_cache("path", "")
        assert mode == stat.S_IMODE(os.lstat(cfg.data_path("path")).st_mode)

    def test_write_datetime(self, tmpdir):
        cfg = UAConfig({"data_dir": tmpdir.strpath})
        key = "test_key"
        dt = datetime.datetime.now()
        cfg.write_cache(key, dt)
        with open(cfg.data_path(key)) as f:
            assert dt.isoformat() == f.read().strip('"')


class TestReadCache:
    @pytest.mark.parametrize("key,path_basename", KNOWN_DATA_PATHS)
    def test_read_cache_returns_none_when_data_path_absent(
        self, tmpdir, key, path_basename
    ):
        """Return None when the specified key data_path is not cached."""
        cfg = UAConfig({"data_dir": tmpdir.strpath})
        assert None is cfg.read_cache(key)
        assert not tmpdir.join(path_basename).check()

    @pytest.mark.parametrize("key,path_basename", KNOWN_DATA_PATHS)
    def test_read_cache_returns_content_when_data_path_present(
        self, tmpdir, key, path_basename
    ):
        cfg = UAConfig({"data_dir": tmpdir.strpath})
        os.makedirs(tmpdir.join(PRIVATE_SUBDIR).strpath)
        data_path = tmpdir.join(PRIVATE_SUBDIR, path_basename)
        with open(data_path.strpath, "w") as f:
            f.write("content{}".format(key))

        assert "content{}".format(key) == cfg.read_cache(key)

    @pytest.mark.parametrize("key,path_basename", KNOWN_DATA_PATHS)
    def test_read_cache_returns_stuctured_content_when_json_data_path_present(
        self, tmpdir, key, path_basename
    ):
        cfg = UAConfig({"data_dir": tmpdir.strpath})
        os.makedirs(tmpdir.join(PRIVATE_SUBDIR).strpath)
        data_path = tmpdir.join(PRIVATE_SUBDIR, path_basename)
        expected = {key: "content{}".format(key)}
        with open(data_path.strpath, "w") as f:
            f.write(json.dumps(expected))

        assert expected == cfg.read_cache(key)

    def test_datetimes_are_unserialised(self, tmpdir):
        cfg = UAConfig({"data_dir": tmpdir.strpath})
        os.makedirs(tmpdir.join(PRIVATE_SUBDIR).strpath)
        data_path = tmpdir.join(PRIVATE_SUBDIR, "dt_test")
        with open(data_path.strpath, "w") as f:
            f.write('{"dt": "2019-07-25T14:35:51"}')

        actual = cfg.read_cache("dt_test")
        assert {"dt": datetime.datetime(2019, 7, 25, 14, 35, 51)} == actual


class TestDeleteCache:
    @pytest.mark.parametrize(
        "property_name,data_path_name,expected_null_value",
        (("machine_token", "machine-token", None),),
    )
    def test_delete_cache_properly_clears_all_caches_simple(
        self, tmpdir, property_name, data_path_name, expected_null_value
    ):
        """
        Ensure that delete_cache clears the cache for simple attributes

        (Simple in this context means those that are simply read from the
        filesystem and returned.)
        """
        property_value = "our-value"
        cfg = UAConfig({"data_dir": tmpdir.strpath})

        data_path = cfg.data_path(data_path_name)
        os.makedirs(os.path.dirname(data_path))
        with open(data_path, "w") as f:
            f.write(property_value)

        before_prop_value = getattr(cfg, property_name)
        assert before_prop_value == property_value

        cfg.delete_cache()

        after_prop_value = getattr(cfg, property_name)
        assert expected_null_value == after_prop_value

    def test_delete_cache_unsets_entitlements(self, tmpdir):
        """The delete_cache unsets any cached entitlements content."""
        cfg = UAConfig({"data_dir": tmpdir.strpath})
        token = {
            "machineTokenInfo": {
                "contractInfo": {
                    "resourceEntitlements": [
                        {"type": "entitlement1", "entitled": True}
                    ]
                }
            }
        }
        cfg.write_cache("machine-token", token)
        previous_entitlements = {
            "entitlement1": {
                "entitlement": {"type": "entitlement1", "entitled": True}
            }
        }
        assert previous_entitlements == cfg.entitlements
        cfg.delete_cache()
        assert {} == cfg.entitlements

    def test_delete_cache_removes_any_cached_data_path_files(self, tmpdir):
        """Any cached files defined in cfg.data_paths will be removed."""
        cfg = UAConfig({"data_dir": tmpdir.strpath})
        # Create half of the cached files, but not all
        odd_keys = list(cfg.data_paths.keys())[::2]
        for odd_key in odd_keys:
            cfg.write_cache(odd_key, odd_key)

        present_files = list(
            itertools.chain(
                *[walk_entry[2] for walk_entry in os.walk(tmpdir.strpath)]
            )
        )
        assert len(odd_keys) == len(present_files)
        cfg.delete_cache()
        dirty_files = list(
            itertools.chain(
                *[walk_entry[2] for walk_entry in os.walk(tmpdir.strpath)]
            )
        )
        assert 0 == len(dirty_files), "{} files not deleted".format(
            len(dirty_files)
        )

    def test_delete_cache_ignores_files_not_defined_in_data_paths(
        self, tmpdir
    ):
        """Any files in data_dir undefined in cfg.data_paths will remain."""
        cfg = UAConfig({"data_dir": tmpdir.strpath})
        t_file = tmpdir.join(PRIVATE_SUBDIR, "otherfile")
        os.makedirs(os.path.dirname(t_file.strpath))
        with open(t_file.strpath, "w") as f:
            f.write("content")
        assert [os.path.basename(t_file.strpath)] == os.listdir(
            tmpdir.join(PRIVATE_SUBDIR).strpath
        )
        cfg.delete_cache()
        assert [os.path.basename(t_file.strpath)] == os.listdir(
            tmpdir.join(PRIVATE_SUBDIR).strpath
        )


class TestStatus:
    @mock.patch("uaclient.contract.get_available_resources")
    @mock.patch("uaclient.config.os.getuid", return_value=0)
    def test_root_unattached(self, _m_getuid, m_get_available_resources):
        """Test we get the correct status dict when unattached"""
        cfg = FakeConfig({})
        m_get_available_resources.return_value = [
            {"name": "esm-infra", "available": True},
            {"name": "fips", "available": False},
        ]
        esm_desc = ENTITLEMENT_CLASS_BY_NAME["esm-infra"].description
        fips_desc = ENTITLEMENT_CLASS_BY_NAME["fips"].description
        expected = copy.deepcopy(DEFAULT_STATUS)
        expected["services"] = [
            {"available": "yes", "name": "esm-infra", "description": esm_desc},
            {"available": "no", "name": "fips", "description": fips_desc},
        ]
        assert expected == cfg.status()

    @pytest.mark.parametrize(
        "resources,get_avail_resp",
        (
            (
                entitlements.ENTITLEMENT_CLASS_BY_NAME.keys(),
                RESP_ALL_RESOURCES_AVAILABLE,
            ),
            ("fips", RESP_ONLY_FIPS_RESOURCE_AVAILABLE),
        ),
    )
    @mock.patch("uaclient.contract.get_available_resources")
    @mock.patch("uaclient.config.os.getuid", return_value=0)
    def test_root_attached(
        self, _m_getuid, m_get_available_resources, resources, get_avail_resp
    ):
        """Test we get the correct status dict when attached with basic conf"""
        cfg = FakeConfig.for_attached_machine()
        expected_services = [
            {
                "description": cls.description,
                "entitled": status.ContractStatus.UNENTITLED.value,
                "name": cls.name,
                "status": status.UserFacingStatus.UNAVAILABLE.value,
                "statusDetails": mock.ANY,
            }
            for cls in entitlements.ENTITLEMENT_CLASSES
        ]
        m_get_available_resources.return_value = get_avail_resp
        expected = copy.deepcopy(DEFAULT_STATUS)
        expected.update(
            {
                "account-id": "acct-1",
                "account": "test_account",
                "attached": True,
                "services": expected_services,
                "subscription-id": "contract-1",
                "subscription": "test_contract",
            }
        )
        assert expected == cfg.status()
        # cfg.status() idempotent
        assert expected == cfg.status()

    @mock.patch("uaclient.contract.get_available_resources")
    @mock.patch("uaclient.config.os.getuid")
    def test_nonroot_unattached_is_same_as_unattached_root(
        self, m_getuid, m_get_available_resources
    ):
        m_get_available_resources.return_value = [
            {"name": "esm-infra", "available": True}
        ]
        m_getuid.return_value = 1000
        cfg = FakeConfig()

        nonroot_status = cfg.status()

        m_getuid.return_value = 0
        root_unattached_status = cfg.status()

        assert root_unattached_status == nonroot_status

    @mock.patch("uaclient.contract.get_available_resources")
    @mock.patch("uaclient.config.os.getuid")
    def test_root_followed_by_nonroot(
        self, m_getuid, m_get_available_resources, tmpdir
    ):
        """Ensure that non-root run after root returns data"""
        cfg = UAConfig({"data_dir": tmpdir.strpath})

        # Run as root
        m_getuid.return_value = 0
        before = copy.deepcopy(cfg.status())

        # Replicate an attach by modifying the underlying config and confirm
        # that we see different status
        other_cfg = FakeConfig.for_attached_machine()
        cfg.write_cache("accounts", {"accounts": other_cfg.accounts})
        cfg.write_cache("machine-token", other_cfg.machine_token)
        assert cfg._attached_status() != before

        # Run as regular user and confirm that we see the result from
        # last time we called .status()
        m_getuid.return_value = 1000
        after = cfg.status()

        assert before == after

    @mock.patch("uaclient.contract.get_available_resources", return_value=[])
    @mock.patch("uaclient.config.os.getuid", return_value=0)
    def test_cache_file_is_written_world_readable(
        self, _m_getuid, _m_get_available_resources, tmpdir
    ):
        cfg = UAConfig({"data_dir": tmpdir.strpath})
        cfg.status()

        assert 0o644 == stat.S_IMODE(
            os.lstat(cfg.data_path("status-cache")).st_mode
        )

    @pytest.mark.parametrize(
        "entitlements",
        (
            [],
            [
                {
                    "type": "support",
                    "entitled": True,
                    "affordances": {"supportLevel": "anything"},
                }
            ],
        ),
    )
    @mock.patch("uaclient.contract.get_available_resources")
    @mock.patch("uaclient.config.os.getuid", return_value=0)
    @mock.patch(M_PATH + "livepatch.LivepatchEntitlement.user_facing_status")
    @mock.patch(M_PATH + "livepatch.LivepatchEntitlement.contract_status")
    @mock.patch(M_PATH + "repo.RepoEntitlement.user_facing_status")
    @mock.patch(M_PATH + "repo.RepoEntitlement.contract_status")
    def test_attached_reports_contract_and_service_status(
        self,
        m_repo_contract_status,
        m_repo_uf_status,
        m_livepatch_contract_status,
        m_livepatch_uf_status,
        _m_getuid,
        m_get_available_resources,
        entitlements,
    ):
        """When attached, return contract and service user-facing status."""
        m_get_available_resources.return_value = RESP_ALL_RESOURCES_AVAILABLE
        m_repo_contract_status.return_value = status.ContractStatus.ENTITLED
        m_repo_uf_status.return_value = (
            status.UserFacingStatus.INAPPLICABLE,
            "repo details",
        )
        m_livepatch_contract_status.return_value = (
            status.ContractStatus.ENTITLED
        )
        m_livepatch_uf_status.return_value = (
            status.UserFacingStatus.ACTIVE,
            "livepatch details",
        )
        token = {
            "machineTokenInfo": {
                "accountInfo": {"id": "acct-1", "name": "accountname"},
                "contractInfo": {
                    "id": "contract-1",
                    "name": "contractname",
                    "resourceEntitlements": entitlements,
                },
            }
        }
        cfg = FakeConfig.for_attached_machine(
            account_name="accountname", machine_token=token
        )
        if not entitlements:
            support_level = status.UserFacingStatus.INAPPLICABLE.value
        else:
            support_level = entitlements[0]["affordances"]["supportLevel"]
        expected = copy.deepcopy(DEFAULT_STATUS)
        expected.update(
            {
                "attached": True,
                "account": "accountname",
                "account-id": "acct-1",
                "subscription": "contractname",
                "subscription-id": "contract-1",
                "techSupportLevel": support_level,
            }
        )
        for cls in ENTITLEMENT_CLASSES:
            if cls.name == "livepatch":
                expected_status = status.UserFacingStatus.ACTIVE.value
                details = "livepatch details"
            else:
                expected_status = status.UserFacingStatus.INAPPLICABLE.value
                details = "repo details"
            expected["services"].append(
                {
                    "name": cls.name,
                    "description": cls.description,
                    "entitled": status.ContractStatus.ENTITLED.value,
                    "status": expected_status,
                    "statusDetails": details,
                }
            )
        assert expected == cfg.status()
        assert len(ENTITLEMENT_CLASSES) - 1 == m_repo_uf_status.call_count
        assert 1 == m_livepatch_uf_status.call_count

    @mock.patch("uaclient.contract.get_available_resources")
    @mock.patch("uaclient.config.os.getuid")
    def test_expires_handled_appropriately(
        self, m_getuid, _m_get_available_resources
    ):
        token = {
            "machineTokenInfo": {
                "accountInfo": {"id": "acct-1", "name": "accountname"},
                "contractInfo": {
                    "id": "contract-1",
                    "name": "contractname",
                    "effectiveTo": "2020-07-18T00:00:00Z",
                    "resourceEntitlements": [],
                },
            }
        }
        cfg = FakeConfig.for_attached_machine(
            account_name="accountname", machine_token=token
        )

        # Test that root's status works as expected (including the cache write)
        m_getuid.return_value = 0
        expected_dt = datetime.datetime(2020, 7, 18, 0, 0, 0)
        assert expected_dt == cfg.status()["expires"]

        # Test that the read from the status cache work properly for non-root
        # users
        m_getuid.return_value = 1000
        assert expected_dt == cfg.status()["expires"]

    @mock.patch("uaclient.config.os.getuid")
    def test_nonroot_user_uses_cache_if_available(self, m_getuid, tmpdir):
        m_getuid.return_value = 1000

        status = {"pass": True}
        cfg = UAConfig({"data_dir": tmpdir.strpath})
        cfg.write_cache("status-cache", status)

        assert status == cfg.status()


ATTACHED_SERVICE_STATUS_PARAMETERS = [
    # ENTITLED => display the given user-facing status
    (ContractStatus.ENTITLED, UserFacingStatus.ACTIVE, False, "enabled"),
    (ContractStatus.ENTITLED, UserFacingStatus.INACTIVE, False, "disabled"),
    (ContractStatus.ENTITLED, UserFacingStatus.INAPPLICABLE, False, "n/a"),
    (ContractStatus.ENTITLED, UserFacingStatus.UNAVAILABLE, False, "—"),
    # UNENTITLED => UNAVAILABLE
    (ContractStatus.UNENTITLED, UserFacingStatus.ACTIVE, False, "—"),
    (ContractStatus.UNENTITLED, UserFacingStatus.INACTIVE, False, "—"),
    (ContractStatus.UNENTITLED, UserFacingStatus.INAPPLICABLE, False, "—"),
    (ContractStatus.UNENTITLED, UserFacingStatus.UNAVAILABLE, [], "—"),
    # ENTITLED but in unavailable_resources => INAPPLICABLE
    (ContractStatus.ENTITLED, UserFacingStatus.ACTIVE, True, "n/a"),
    (ContractStatus.ENTITLED, UserFacingStatus.INACTIVE, True, "n/a"),
    (ContractStatus.ENTITLED, UserFacingStatus.INAPPLICABLE, True, "n/a"),
    (ContractStatus.ENTITLED, UserFacingStatus.UNAVAILABLE, True, "n/a"),
    # UNENTITLED and in unavailable_resources => UNAVAILABLE
    (ContractStatus.UNENTITLED, UserFacingStatus.ACTIVE, True, "—"),
    (ContractStatus.UNENTITLED, UserFacingStatus.INACTIVE, True, "—"),
    (ContractStatus.UNENTITLED, UserFacingStatus.INAPPLICABLE, True, "—"),
    (ContractStatus.UNENTITLED, UserFacingStatus.UNAVAILABLE, True, "—"),
]


class TestAttachedServiceStatus:
    @pytest.mark.parametrize(
        "contract_status,uf_status,in_inapplicable_resources,expected_status",
        ATTACHED_SERVICE_STATUS_PARAMETERS,
    )
    def test_status(
        self,
        contract_status,
        uf_status,
        in_inapplicable_resources,
        expected_status,
    ):
        ent = mock.MagicMock()
        ent.name = "test_entitlement"
        ent.contract_status.return_value = contract_status
        ent.user_facing_status.return_value = (uf_status, "")

        unavailable_resources = [ent.name] if in_inapplicable_resources else []
        ret = FakeConfig()._attached_service_status(ent, unavailable_resources)

        assert expected_status == ret["status"]


class TestParseConfig:
    @mock.patch("uaclient.config.os.path.exists", return_value=False)
    def test_parse_config_uses_defaults_when_no_config_present(self, m_exists):
        cwd = os.getcwd()
        with mock.patch.dict("uaclient.config.os.environ", values={}):
            config = parse_config()
        expected_calls = [
            mock.call("{}/uaclient.conf".format(cwd)),
            mock.call("/etc/ubuntu-advantage/uaclient.conf"),
        ]
        assert expected_calls == m_exists.call_args_list
        expected_default_config = {
            "contract_url": "https://contracts.canonical.com",
            "data_dir": "/var/lib/ubuntu-advantage",
            "log_file": "/var/log/ubuntu-advantage.log",
            "log_level": "INFO",
        }
        assert expected_default_config == config

    @mock.patch("uaclient.config.os.path.exists", return_value=False)
    def test_parse_config_scrubs_user_environ_values(self, m_exists):
        user_values = {
            "UA_CONTRACT_URL": "https://contract",
            "ua_data_dir": "~/somedir",
            "Ua_LoG_FiLe": "some.log",
            "UA_LOG_LEVEL": "debug",
        }
        with mock.patch.dict("uaclient.config.os.environ", values=user_values):
            config = parse_config()
        expanded_dir = os.path.expanduser("~")
        expected_default_config = {
            "contract_url": "https://contract",
            "data_dir": "{}/somedir".format(expanded_dir),
            "log_file": "some.log",
            "log_level": "DEBUG",
        }
        assert expected_default_config == config

    @mock.patch("uaclient.config.os.path.exists", return_value=False)
    def test_parse_raises_errors_on_invalid_urls(self, m_exists):
        user_values = {
            "UA_CONTRACT_URL": "htp://contract"  # no acceptable url scheme
        }
        with mock.patch.dict("uaclient.config.os.environ", values=user_values):
            with pytest.raises(exceptions.UserFacingError) as excinfo:
                parse_config()
        expected_msg = "Invalid url in config. contract_url: htp://contract"
        assert expected_msg == excinfo.value.msg
