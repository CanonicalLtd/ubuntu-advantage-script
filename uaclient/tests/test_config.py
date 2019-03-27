import json
import os

from nose2.tools.params import params

from uaclient.config import UAConfig
from uaclient.testing.helpers import TestCase


# These are in a variable rather than inline to work around
# https://github.com/nose-devs/nose2/issues/433
SIMPLE_PARAMS = (('machine_token', 'machine-token', None),
                 ('contracts', 'account-contracts', []))

KNOWN_DATA_PATHS = (('bound-macaroon', 'bound-macaroon'),
                    ('accounts', 'accounts.json'))


class TestAccounts(TestCase):

    with_logs = True

    def test_accounts_returns_empty_list_when_no_cached_account_value(self):
        """Config.accounts property returns an empty list when no cache."""
        tmp_dir = self.tmp_dir()
        cfg = UAConfig({'data_dir': tmp_dir})

        assert [] == cfg.accounts

    def test_accounts_extracts_accounts_key_from_read_cache(self):
        """Config.accounts property extracts the accounts key from cache."""
        tmp_dir = self.tmp_dir()
        cfg = UAConfig({'data_dir': tmp_dir})
        cfg.write_cache('accounts', {'accounts': ['acct1', 'acct2']})

        assert ['acct1', 'acct2'] == cfg.accounts

    def test_accounts_logs_warning_when_non_dictionary_cache_content(self):
        """Config.accounts warns and returns empty list on non-dict cache."""
        tmp_dir = self.tmp_dir()
        cfg = UAConfig({'data_dir': tmp_dir})
        cfg.write_cache('accounts', 'non-dict-value')

        assert [] == cfg.accounts
        expected_warning = (
            "WARNING: Unexpected type <class 'str'> in cache %s" % (
                self.tmp_path('accounts.json', tmp_dir)))
        assert expected_warning in self.logs

    def test_accounts_logs_warning_when_missing_accounts_key_in_cache(self):
        """Config.accounts warns when missing 'accounts' key in cache"""
        tmp_dir = self.tmp_dir()
        cfg = UAConfig({'data_dir': tmp_dir})
        cfg.write_cache('accounts', {'non-accounts': 'somethingelse'})

        assert [] == cfg.accounts
        expected_warning = (
            "WARNING: Missing 'accounts' key in cache %s" %
            self.tmp_path('accounts.json', tmp_dir))
        assert expected_warning in self.logs

    def test_accounts_logs_warning_when_non_list_accounts_cache_content(self):
        """Config.accounts warns on non-list accounts key."""
        tmp_dir = self.tmp_dir()
        cfg = UAConfig({'data_dir': tmp_dir})
        cfg.write_cache('accounts', {'accounts': 'non-list-value'})

        assert [] == cfg.accounts
        expected_warning = (
            "WARNING: Unexpected 'accounts' type <class 'str'> in cache %s" % (
                self.tmp_path('accounts.json', tmp_dir)))
        assert expected_warning in self.logs


class TestDataPath(TestCase):

    def test_data_path_returns_data_dir_path_without_key(self):
        """The data_path method returns the data_dir when key is absent."""
        cfg = UAConfig({'data_dir': '/my/dir'})
        assert '/my/dir' == cfg.data_path()

    @params(*KNOWN_DATA_PATHS)
    def test_data_path_returns_file_path_with_defined_data_paths(
            self, key, path_basename):
        """When key is defined in Config.data_paths return data_path value."""
        cfg = UAConfig({'data_dir': '/my/dir'})
        assert '/my/dir/%s' % path_basename == cfg.data_path(key=key)

    @params(('notHere', 'notHere'), ('anything', 'anything'))
    def test_data_path_returns_file_path_with_undefined_data_paths(
            self, key, path_basename):
        """When key is not in Config.data_paths the key is used to data_dir"""
        cfg = UAConfig({'data_dir': '/my/dir'})
        assert '/my/dir/%s' % key == cfg.data_path(key=key)


class TestWriteCache(TestCase):

    @params(('unknownkey', 'content1'), ('another-one', 'content2'))
    def test_write_cache_write_key_name_in_data_dir_when_data_path_absent(
            self, key, content):
        """When key is not in data_paths, write content to data_dir/key."""
        tmp_dir = self.tmp_dir()
        cfg = UAConfig({'data_dir': tmp_dir})
        expected_path = os.path.join(tmp_dir, key)

        assert False is os.path.exists(expected_path), (
            'Found unexpected file %s' % expected_path)
        assert None is cfg.write_cache(key, content)
        assert True is os.path.exists(expected_path), (
            'Missing expected file %s' % expected_path)
        assert content == cfg.read_cache(key)

    def test_write_cache_creates_dir_when_data_dir_does_not_exist(self):
        """When data_dir doesn't exist, create it."""
        tmp_subdir = self.tmp_path('does/not/exist')
        cfg = UAConfig({'data_dir': tmp_subdir})

        assert False is os.path.isdir(tmp_subdir), (
            'Found unexpected directory %s' % tmp_subdir)
        assert None is cfg.write_cache('somekey', 'someval')
        assert True is os.path.isdir(tmp_subdir), (
            'Missing expected directory %s' % tmp_subdir)
        assert 'someval' == cfg.read_cache('somekey')

    @params(('dictkey', {'1': 'v1'}), ('listkey', [1, 2, 3]))
    def test_write_cache_writes_json_string_when_content_not_a_string(
            self, key, value):
        """When content is not a string, write a json string."""
        tmp_dir = self.tmp_dir()
        cfg = UAConfig({'data_dir': tmp_dir})

        expected_json_content = json.dumps(value)
        assert None is cfg.write_cache(key, value)
        with open(self.tmp_path(key, tmp_dir), 'r') as stream:
            assert expected_json_content == stream.read()
        assert value == cfg.read_cache(key)


class TestReadCache(TestCase):

    @params(*KNOWN_DATA_PATHS)
    def test_read_cache_returns_none_when_data_path_absent(
            self, key, path_basename):
        """Return None when the specified key data_path is not cached."""
        tmp_dir = self.tmp_dir()
        cfg = UAConfig({'data_dir': tmp_dir})
        assert None is cfg.read_cache(key)
        assert False is os.path.exists(os.path.join(tmp_dir, path_basename))

    @params(*KNOWN_DATA_PATHS)
    def test_read_cache_returns_content_when_data_path_present(
            self, key, path_basename):
        tmp_dir = self.tmp_dir()
        cfg = UAConfig({'data_dir': tmp_dir})
        data_path = self.tmp_path(path_basename, tmp_dir)
        with open(data_path, 'w') as f:
            f.write('content%s' % key)

        assert 'content%s' % key == cfg.read_cache(key)

    @params(*KNOWN_DATA_PATHS)
    def test_read_cache_returns_stuctured_content_when_json_data_path_present(
            self, key, path_basename):
        tmp_dir = self.tmp_dir()
        cfg = UAConfig({'data_dir': tmp_dir})
        data_path = self.tmp_path(path_basename, tmp_dir)
        expected = {key: 'content%s' % key}
        with open(data_path, 'w') as f:
            f.write(json.dumps(expected))

        assert expected == cfg.read_cache(key)


class TestDeleteCache(TestCase):

    @params(*SIMPLE_PARAMS)
    def test_delete_cache_properly_clears_all_caches_simple(
            self, property_name, data_path_name, expected_null_value):
        """
        Ensure that delete_cache clears the cache for simple attributes

        (Simple in this context means those that are simply read from the
        filesystem and returned.)
        """
        property_value = 'our-value'
        tmp_dir = self.tmp_dir()
        cfg = UAConfig({'data_dir': tmp_dir})

        data_path = cfg.data_path(data_path_name)
        with open(data_path, 'w') as f:
            f.write(property_value)

        before_prop_value = getattr(cfg, property_name)
        assert before_prop_value == property_value

        cfg.delete_cache()

        after_prop_value = getattr(cfg, property_name)
        assert expected_null_value == after_prop_value

    def test_delete_cache_unsets_entitlements(self):
        """The delete_cache unsets any cached entitlements content."""
        tmp_dir = self.tmp_dir()
        cfg = UAConfig({'data_dir': tmp_dir})
        token = {
            'machineTokenInfo': {'contractInfo': {'resourceEntitlements': [{
                'type': 'entitlement1', 'entitled': True}]}}}
        cfg.write_cache('machine-token', token)
        previous_entitlements = {
            'entitlement1': {'entitlement':
                                {'type': 'entitlement1', 'entitled': True}}}
        assert previous_entitlements == cfg.entitlements
        cfg.delete_cache()
        assert {} == cfg.entitlements

    def test_delete_cache_removes_any_cached_data_path_files(self):
        """Any cached files defined in cfg.data_paths will be removed."""
        tmp_dir = self.tmp_dir()
        cfg = UAConfig({'data_dir': tmp_dir})
        # Create half of the cached files, but not all
        odd_keys = list(cfg.data_paths.keys())[::2]
        for odd_key in odd_keys:
            cfg.write_cache(odd_key, odd_key)

        assert len(odd_keys) == len(os.listdir(tmp_dir))
        cfg.delete_cache()
        dirty_files = os.listdir(tmp_dir)
        assert 0 == len(dirty_files), '%d files not deleted' % len(dirty_files)

    def test_delete_cache_ignores_files_not_defined_in_data_paths(self):
        """Any files in data_dir undefined in cfg.data_paths will remain."""
        tmp_dir = self.tmp_dir()
        cfg = UAConfig({'data_dir': tmp_dir})
        t_file = self.tmp_path('otherfile', tmp_dir)
        with open(t_file, 'w') as f:
            f.write('content')
        assert [os.path.basename(t_file)] == os.listdir(tmp_dir)
        cfg.delete_cache()
        assert [os.path.basename(t_file)] == os.listdir(tmp_dir)
