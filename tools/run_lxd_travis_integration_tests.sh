#!/bin/bash
source tools/base_travis_integration_tests.sh

install_lxd() {
  sudo snap install lxd
  sudo lxd init --auto
  sudo usermod -a -G lxd $USER
}

copy_deb_packages

if [ "$TRAVIS_EVENT_TYPE" = "cron" ]; then
  BUILD_PR=0
  if [ "$TRAVIS_BRANCH" != "${TRAVIS_BRANCH/release-}" ]; then
      # Run cron of release-XX branches against UA_STAGING_PPA
      export UACLIENT_BEHAVE_PPA=${UA_STAGING_PPA}
      export UACLIENT_BEHAVE_PPA_KEYID=${UA_STAGING_PPA_KEYID}
  fi
else
  create_pr_tar_file
fi

# Because we are using dist:bionic for the travis host, we need
# to remove the lxd deb-installed package to avoid
# confusion over lxd versions
remove_lxd

install_lxd
sg lxd -c "UACLIENT_BEHAVE_BUILD_PR=${BUILD_PR} make test"
