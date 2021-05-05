@uses.config.contract_token_staging
Feature: Enable command behaviour when attached to an UA staging subscription

    @series.xenial
    Scenario: Attached enable CC EAL service in a xenial lxd container
        Given a `xenial` machine with ubuntu-advantage-tools installed
        When I attach `contract_token_staging` with sudo
        Then I verify that running `ua enable cc-eal` `as non-root` exits `1`
        And I will see the following on stderr:
            """
            This command must be run as root (try using sudo).
            """
        When I run `ua enable cc-eal --beta` with sudo
        Then I will see the following on stdout:
            """
            One moment, checking your subscription first
            GPG key '/usr/share/keyrings/ubuntu-cc-keyring.gpg' not found.
            """ 

    @series.xenial
    @series.bionic
    @series.focal
    Scenario Outline: Attached enable esm-apps on a machine
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I attach `contract_token_staging` with sudo
        And I run `ua status --all` as non-root
        Then stdout matches regexp
        """
        esm-apps      yes                enabled            UA Apps: Extended Security Maintenance \(ESM\)
        """
        And I verify that running `apt update` `with sudo` exits `0`
        When I run `apt-cache policy` as non-root
        Then apt-cache policy for the following url has permission `500`
        """
        https://esm.staging.ubuntu.com/apps/ubuntu <release>-apps-updates/main amd64 Packages
        """
        And apt-cache policy for the following url has permission `500`
        """
        https://esm.staging.ubuntu.com/apps/ubuntu <release>-apps-security/main amd64 Packages
        """
        And I verify that running `apt update` `with sudo` exits `0`
        When I run `apt install -y <apps-pkg>` with sudo, retrying exit [100]
        And I run `apt-cache policy <apps-pkg>` as non-root
        Then stdout matches regexp:
        """
        Version table:
        \s*\*\*\* .* 500
        \s*500 https://esm.staging.ubuntu.com/apps/ubuntu <release>-apps-security/main amd64 Packages
        """
        When I run `mkdir -p /var/lib/ubuntu-advantage/messages` with sudo
        When I create the file `/var/lib/ubuntu-advantage/messages/apt-pre-invoke-no-packages-infra.tmpl` with the following
        """
        esm-infra-no {ESM_INFRA_PKG_COUNT}:{ESM_INFRA_PACKAGES}
        """
        When I create the file `/var/lib/ubuntu-advantage/messages/apt-pre-invoke-packages-infra.tmpl` with the following
        """
        esm-infra {ESM_INFRA_PKG_COUNT}:{ESM_INFRA_PACKAGES}
        """
        When I create the file `/var/lib/ubuntu-advantage/messages/apt-pre-invoke-packages-apps.tmpl` with the following
        """
        esm-apps {ESM_APPS_PKG_COUNT}:{ESM_APPS_PACKAGES}
        """
        When I create the file `/var/lib/ubuntu-advantage/messages/apt-pre-invoke-no-packages-apps.tmpl` with the following
        """
        esm-apps-no {ESM_APPS_PKG_COUNT}:{ESM_APPS_PACKAGES}
        """
        When I run `/usr/lib/ubuntu-advantage/apt-esm-hook process-templates` with sudo
        When I run `cat /var/lib/ubuntu-advantage/messages/apt-pre-invoke-packages-apps` with sudo
        Then stdout matches regexp:
        """
        esm-apps(-no)? \d+:(.*)?
        """
        When I run `cat /var/lib/ubuntu-advantage/messages/apt-pre-invoke-packages-infra` with sudo
        Then stdout matches regexp:
        """
        esm-infra(-no)? \d+:(.*)?
        """
        When I create the file `/var/lib/ubuntu-advantage/messages/apt-pre-invoke-packages-infra.tmpl` with the following
        """
        esm-infra {ESM_INFRA_PKG_COUNT} {ESM_INFRA_PACKAGES}
        """
        When I create the file `/var/lib/ubuntu-advantage/messages/apt-pre-invoke-no-packages-infra.tmpl` with the following
        """
        esm-infra-no {ESM_INFRA_PKG_COUNT} {ESM_INFRA_PACKAGES}
        """
        When I create the file `/var/lib/ubuntu-advantage/messages/apt-pre-invoke-packages-apps.tmpl` with the following
        """
        esm-apps {ESM_APPS_PKG_COUNT} {ESM_APPS_PACKAGES}
        """
        When I run `apt upgrade --dry-run` with sudo
        Then stdout matches regexp:
        """
        esm-apps(-no)? \d+.*

        esm-infra(-no)? \d+.*
        """

        Examples: ubuntu release
           | release | apps-pkg |
           | bionic  | bundler  |
           | focal   | ant      |
           | xenial  | jq       |

    @series.xenial
    @series.bionic
    @uses.config.machine_type.lxd.vm
    Scenario Outline: Attached enable of vm-based services in an ubuntu lxd vm
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I attach `contract_token_staging` with sudo
        And I run `ua disable livepatch` with sudo
        And I run `apt-get install openssh-client openssh-server strongswan -y` with sudo, retrying exit [100]
        And I run `apt-mark hold openssh-client openssh-server strongswan` with sudo
        And I run `ua enable <fips-service> --assume-yes` with sudo
        Then stdout matches regexp:
            """
            Updating package lists
            Installing <fips-name> packages
            <fips-name> enabled
            A reboot is required to complete install
            """
        When I run `ua status --all` with sudo
        Then stdout matches regexp:
            """
            <fips-service> +yes                enabled
            """
        And stdout matches regexp:
            """
            FIPS support requires system reboot to complete configuration
            """
        And I verify that running `apt update` `with sudo` exits `0`
        And I verify that `openssh-server` is installed from apt source `<fips-apt-source>`
        And I verify that `openssh-client` is installed from apt source `<fips-apt-source>`
        And I verify that `strongswan` is installed from apt source `<fips-apt-source>`
        And I verify that `openssh-server-hmac` is installed from apt source `<fips-apt-source>`
        And I verify that `openssh-client-hmac` is installed from apt source `<fips-apt-source>`
        And I verify that `strongswan-hmac` is installed from apt source `<fips-apt-source>`
        When I reboot the `<release>` machine
        And  I run `uname -r` as non-root
        Then stdout matches regexp:
            """
            fips
            """
        When I run `cat /proc/sys/crypto/fips_enabled` with sudo
        Then I will see the following on stdout:
        """
        1
        """
        When I run `ua status --all` with sudo
        Then stdout does not match regexp:
            """
            FIPS support requires system reboot to complete configuration
            """
        When I run `ua disable <fips-service> --assume-yes` with sudo
        Then stdout matches regexp:
            """
            Updating package lists
            A reboot is required to complete disable operation
            """
        When I run `ua status --all` with sudo
        Then stdout matches regexp:
            """
            Disabling FIPS requires system reboot to complete operation
            """
        When I run `apt-cache policy ubuntu-fips` as non-root
        Then stdout matches regexp:
        """
        .*Installed: \(none\)
        """
        When I reboot the `<release>` machine
        Then I verify that `openssh-server` installed version matches regexp `fips`
        And I verify that `openssh-client` installed version matches regexp `fips`
        And I verify that `strongswan` installed version matches regexp `fips`
        And I verify that `openssh-server-hmac` installed version matches regexp `fips`
        And I verify that `openssh-client-hmac` installed version matches regexp `fips`
        And I verify that `strongswan-hmac` installed version matches regexp `fips`
        When I run `apt-mark unhold openssh-client openssh-server strongswan` with sudo
        Then I will see the following on stdout:
        """
        openssh-client was already not hold.
        openssh-server was already not hold.
        strongswan was already not hold.
        """
        When I run `ua status --all` with sudo
        Then stdout matches regexp:
            """
            <fips-service> +yes                disabled
            """
        Then stdout does not match regexp:
            """
            Disabling FIPS requires system reboot to complete operation
            """

        Examples: ubuntu release
           | release | fips-name    | fips-service |fips-apt-source                                        |
           | xenial  | FIPS         | fips         |https://esm.staging.ubuntu.com/fips/ubuntu xenial/main |
           | bionic  | FIPS         | fips         |https://esm.staging.ubuntu.com/fips/ubuntu bionic/main |

    @series.xenial
    @series.bionic
    @uses.config.machine_type.lxd.vm
    Scenario Outline: Attached enable of vm-based services in an ubuntu lxd vm
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I attach `contract_token_staging` with sudo
        And I run `ua disable livepatch` with sudo
        And I run `apt-get install openssh-client openssh-server strongswan -y` with sudo, retrying exit [100]
        When I run `ua enable <fips-service> --assume-yes` with sudo
        Then stdout matches regexp:
            """
            Updating package lists
            Installing <fips-name> packages
            <fips-name> enabled
            A reboot is required to complete install
            """
        When I run `ua status --all` with sudo
        Then stdout matches regexp:
            """
            <fips-service> +yes                enabled
            """
        And I verify that running `apt update` `with sudo` exits `0`
        And I verify that `openssh-server` is installed from apt source `<fips-apt-source>`
        And I verify that `openssh-client` is installed from apt source `<fips-apt-source>`
        And I verify that `strongswan` is installed from apt source `<fips-apt-source>`
        And I verify that `openssh-server-hmac` is installed from apt source `<fips-apt-source>`
        And I verify that `openssh-client-hmac` is installed from apt source `<fips-apt-source>`
        And I verify that `strongswan-hmac` is installed from apt source `<fips-apt-source>`
        When I reboot the `<release>` machine
        And  I run `uname -r` as non-root
        Then stdout matches regexp:
            """
            fips
            """
        When I run `cat /proc/sys/crypto/fips_enabled` with sudo
        Then I will see the following on stdout:
        """
        1
        """
        When I run `ua disable <fips-service> --assume-yes` with sudo
        Then stdout matches regexp:
            """
            Updating package lists
            A reboot is required to complete disable operation
            """
        When I reboot the `<release>` machine
        Then I verify that `openssh-server` installed version matches regexp `fips`
        And I verify that `openssh-client` installed version matches regexp `fips`
        And I verify that `strongswan` installed version matches regexp `fips`
        And I verify that `openssh-server-hmac` installed version matches regexp `fips`
        And I verify that `openssh-client-hmac` installed version matches regexp `fips`
        And I verify that `strongswan-hmac` installed version matches regexp `fips`
        When I run `apt-mark unhold openssh-client openssh-server strongswan` with sudo
        Then I will see the following on stdout:
        """
        openssh-client was already not hold.
        openssh-server was already not hold.
        strongswan was already not hold.
        """
        When I run `ua status --all` with sudo
        Then stdout matches regexp:
            """
            <fips-service> +yes                disabled
            """

        Examples: ubuntu release
           | release | fips-name    | fips-service |fips-apt-source                                                        |
           | xenial  | FIPS Updates | fips-updates |https://esm.staging.ubuntu.com/fips-updates/ubuntu xenial-updates/main |
           | bionic  | FIPS Updates | fips-updates |https://esm.staging.ubuntu.com/fips-updates/ubuntu bionic-updates/main |

   @series.xenial
   @uses.config.machine_type.lxd.vm
   Scenario Outline: Attached FIPS upgrade across LTS releases
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I attach `contract_token_staging` with sudo
        And I run `apt-get install lsof` with sudo, retrying exit [100]
        And I run `ua disable livepatch` with sudo
        And I run `ua enable <fips-service> --assume-yes` with sudo
        Then stdout matches regexp:
            """
            Updating package lists
            Installing <fips-name> packages
            <fips-name> enabled
            A reboot is required to complete install
            """
        When I run `ua status --all` with sudo
        Then stdout matches regexp:
            """
            <fips-service> +yes                enabled
            """
        And I verify that running `apt update` `with sudo` exits `0`
        When I reboot the `<release>` machine
        And  I run `uname -r` as non-root
        Then stdout matches regexp:
        """
        fips
        """
        When I run `cat /proc/sys/crypto/fips_enabled` with sudo
        Then I will see the following on stdout:
        """
        1
        """
        When I run `apt-get dist-upgrade -y --allow-downgrades` with sudo
        # A package may need a reboot after running dist-upgrade
        And I reboot the `<release>` machine
        And I create the file `/etc/update-manager/release-upgrades.d/ua-test.cfg` with the following
        """
        [Sources]
        AllowThirdParty=yes
        """
        Then I verify that running `do-release-upgrade --frontend DistUpgradeViewNonInteractive` `with sudo` exits `0`
        When I reboot the `<release>` machine
        And I run `lsb_release -cs` as non-root
        Then I will see the following on stdout:
        """
        <next_release>
        """
        When I verify that running `egrep "disabled" /etc/apt/sources.list.d/<source-file>.list` `as non-root` exits `1`
        Then I will see the following on stdout:
        """
        """
        When I run `ua status --all` with sudo
        Then stdout matches regexp:
        """
        <fips-service> +yes                enabled
        """
        When  I run `uname -r` as non-root
        Then stdout matches regexp:
            """
            fips
            """
        When I run `cat /proc/sys/crypto/fips_enabled` with sudo
        Then I will see the following on stdout:
        """
        1
        """

        Examples: ubuntu release
        | release | next_release | fips-service  | fips-name    | source-file         |
        | xenial  | bionic       | fips          | FIPS         | ubuntu-fips         |
        | xenial  | bionic       | fips-updates  | FIPS Updates | ubuntu-fips-updates |

    @series.xenial
    @series.bionic
    @series.focal
    Scenario Outline: Attached enable of cis service in a ubuntu machine
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I attach `contract_token_staging` with sudo
        And I verify that running `ua enable cis --beta` `with sudo` exits `0`
        Then I will see the following on stdout:
            """
            One moment, checking your subscription first
            Updating package lists
            Installing CIS Audit packages
            CIS Audit enabled
            Refer to /usr/share/doc/usg-common/README.audit.gz on how to run an audit scan of the system
            Refer to /usr/share/doc/usg-cisbenchmark/README.hardening.gz on how to harden the system to the desired CIS compliance level
            """
        When I run `apt-cache policy usg-cisbenchmark` as non-root
        Then stdout does not match regexp:
        """
        .*Installed: \(none\)
        """
        And stdout matches regexp:
        """
        \s* 500 https://esm.staging.ubuntu.com/cis/ubuntu <release>/main amd64 Packages
        """
        When I run `apt-cache policy usg-common` as non-root
        Then stdout does not match regexp:
        """
        .*Installed: \(none\)
        """
        And stdout matches regexp:
        """
        \s* 500 https://esm.staging.ubuntu.com/cis/ubuntu <release>/main amd64 Packages
        """

        Examples: not entitled services
           | release |
           | focal   |
           | bionic  |
           | xenial  |

    @series.xenial
    @series.bionic
    @uses.config.machine_type.lxd.vm
    Scenario Outline: Attached enable fips-updates on fips enabled vm
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I attach `contract_token_staging` with sudo
        And I run `ua disable livepatch` with sudo
        And I run `apt-get install openssh-client openssh-server strongswan -y` with sudo, retrying exit [100]
        And I run `ua enable fips --assume-yes` with sudo
        Then stdout matches regexp:
            """
            Updating package lists
            Installing FIPS packages
            FIPS enabled
            A reboot is required to complete install
            """
        When I run `ua status --all` with sudo
        Then stdout matches regexp:
            """
            fips +yes                enabled
            """
        When I reboot the `<release>` machine
        And  I run `ua enable fips-updates --assume-yes` with sudo
        Then stdout matches regexp:
            """
            Updating package lists
            Installing FIPS Updates packages
            FIPS Updates enabled
            A reboot is required to complete install
            """
        When I run `ua status --all` with sudo
        Then stdout matches regexp:
            """
            fips +yes                n/a
            """
        And stdout matches regexp:
            """
            fips-updates +yes                enabled
            """
        When I reboot the `<release>` machine
        Then I verify that running `apt update` `with sudo` exits `0`
        And I verify that `ubuntu-fips` is installed from apt source `<fips-apt-source>`
        And I verify that `openssh-server` is installed from apt source `<fips-apt-source>`
        And I verify that `openssh-client` is installed from apt source `<fips-apt-source>`
        And I verify that `strongswan` is installed from apt source `<fips-apt-source>`
        And I verify that `openssh-server-hmac` is installed from apt source `<fips-apt-source>`
        And I verify that `openssh-client-hmac` is installed from apt source `<fips-apt-source>`
        And I verify that `strongswan-hmac` is installed from apt source `<fips-apt-source>`
        When  I run `uname -r` as non-root
        Then stdout matches regexp:
            """
            fips
            """
        When I run `cat /proc/sys/crypto/fips_enabled` with sudo
        Then I will see the following on stdout:
        """
        1
        """

        Examples: ubuntu release
           | release | fips-apt-source                                                        |
           | xenial  | https://esm.staging.ubuntu.com/fips-updates/ubuntu xenial-updates/main |
           | bionic  | https://esm.staging.ubuntu.com/fips-updates/ubuntu bionic-updates/main |
