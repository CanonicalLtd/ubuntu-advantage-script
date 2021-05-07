@uses.config.contract_token
Feature: Command behaviour when attaching a machine to an Ubuntu Advantage
        subscription using a valid token

    @series.xenial
    @series.bionic
    @series.focal
    @uses.config.machine_type.lxd.container
    Scenario Outline: Attach command in a ubuntu lxd container
       Given a `<release>` machine with ubuntu-advantage-tools installed
        When I run `apt-get update` with sudo, retrying exit [100]
        And I run `apt-get install -y <downrev_pkg>` with sudo, retrying exit [100]
        And I run `run-parts /etc/update-motd.d/` with sudo
        Then if `<release>` in `xenial` and stdout matches regexp:
        """
        \d+ package(s)? can be updated.
        \d+ of these updates (is a|are) security update(s)?.
        """
        Then if `<release>` in `bionic` and stdout matches regexp:
        """
        \d+ update(s)? can be applied immediately.
        \d+ of these updates (is a|are) standard security update(s)?.
        """
        Then if `<release>` in `focal` and stdout matches regexp:
        """
        \d+ update(s)? can be installed immediately.
        \d+ of these updates (is a|are) security update(s)?.
        """
        When I attach `contract_token` with sudo
        Then stdout matches regexp:
        """
        UA Infra: ESM enabled
        """
        And stdout matches regexp:
        """
        This machine is now attached to
        """
        And stdout matches regexp:
        """
        SERVICE       ENTITLED  STATUS    DESCRIPTION
        esm-infra    +yes      +enabled  +UA Infra: Extended Security Maintenance \(ESM\)
        fips         +yes      +n/a      +NIST-certified FIPS modules
        fips-updates +yes      +n/a      +Uncertified security updates to FIPS modules
        livepatch    +yes      +n/a      +Canonical Livepatch service
        """
        And stderr matches regexp:
        """
        Enabling default service esm-infra
        """
        When I append the following on uaclient config:
            """
            features:
              allow_beta: true
            """
        And I run `apt update` with sudo
        And I run `python3 /usr/lib/ubuntu-advantage/ua_update_messaging.py` with sudo
        And I run `apt install update-motd` with sudo, retrying exit [100]
        And I run `update-motd` with sudo
        Then if `<release>` in `focal` and stdout matches regexp:
        """
        \* Introducing Extended Security Maintenance for Applications.
          +Receive updates to over 30,000 software packages with your
          +Ubuntu Advantage subscription. Free for personal use.

            +https:\/\/ubuntu.com\/esm

        UA (Infra:|Infrastructure) Extended Security Maintenance \(ESM\) is enabled.

        \d+ update(s)? can be installed immediately.
        \d+ of these updates (is|are) (fixed|provided) through UA (Infra:|Infrastructure) ESM.
        \d+ of these updates (is a|are) security update(s)?.
        To see these additional updates run: apt list --upgradable
        """
        Then if `<release>` in `xenial or bionic` and stdout matches regexp:
        """
        \* Introducing Extended Security Maintenance for Applications.
          +Receive updates to over 30,000 software packages with your
          +Ubuntu Advantage subscription. Free for personal use.

            +https:\/\/ubuntu.com\/esm

        UA Infra: Extended Security Maintenance \(ESM\) is enabled.

        \d+ package(s)? can be updated.
        \d+ of these updates (is a|are) security update(s)?.
        To see these additional updates run: apt list --upgradable
        """
        When I update contract to use `effectiveTo` as `days=-20`
        And I run `python3 /usr/lib/ubuntu-advantage/ua_update_messaging.py` with sudo
        And I run `update-motd` with sudo
        Then if `<release>` in `xenial or bionic` and stdout matches regexp:
        """

        \*Your UA Infra: ESM subscription has EXPIRED\*

        \d+ additional security update\(s\) could have been applied via UA Infra: ESM.

        Renew your UA services at https:\/\/ubuntu.com\/esm

        """
        Then if `<release>` in `xenial` and stdout matches regexp:
        """

        Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
        applicable law.

        """
        When I run `apt upgrade --dry-run` with sudo
        Then if `<release>` in `xenial` and stdout matches regexp:
        """
        \*Your UA Infra: ESM subscription has EXPIRED\*
        Enabling UA Infra: ESM service would provide security updates for following
        packages:
          libkrad0
        1 esm-infra security update\(s\) NOT APPLIED. Renew your UA services at
        https:\/\/ubuntu.com\/advantage

        """
        Examples: ubuntu release packages
           | release | downrev_pkg                 |
           | xenial  | libkrad0=1.13.2+dfsg-5      |
           | bionic  | libkrad0=1.16-2build1       |
           | focal   | hello=2.10-2ubuntu2         |

    @series.all
    @uses.config.machine_type.aws.generic
    Scenario Outline: Attach command in an generic AWS Ubuntu VM
       Given a `<release>` machine with ubuntu-advantage-tools installed
        When I attach `contract_token` with sudo
        Then stdout matches regexp:
        """
        UA Infra: ESM enabled
        """
        And stdout matches regexp:
        """
        This machine is now attached to
        """
        And stdout matches regexp:
        """
        SERVICE       ENTITLED  STATUS    DESCRIPTION
        esm-infra    +yes      +enabled  +UA Infra: Extended Security Maintenance \(ESM\)
        fips         +yes      +<fips_status>      +NIST-certified FIPS modules
        fips-updates +yes      +<fips_status>      +Uncertified security updates to FIPS modules
        livepatch    +yes      +<lp_status>  +<lp_desc>
        """
        And stderr matches regexp:
        """
        Enabling default service esm-infra
        """

        Examples: ubuntu release livepatch status
           | release | fips_status |lp_status | lp_desc                       |
           | xenial  | disabled    |enabled   | Canonical Livepatch service   |
           | bionic  | disabled    |enabled   | Canonical Livepatch service   |
           | focal   | n/a         |enabled   | Canonical Livepatch service   |

    @series.all
    @uses.config.machine_type.azure.generic
    Scenario Outline: Attach command in a ubuntu lxd container
       Given a `<release>` machine with ubuntu-advantage-tools installed
        When I attach `contract_token` with sudo
        Then stdout matches regexp:
        """
        UA Infra: ESM enabled
        """
        And stdout matches regexp:
        """
        This machine is now attached to
        """
        And stdout matches regexp:
        """
        SERVICE       ENTITLED  STATUS    DESCRIPTION
        esm-infra    +yes      +enabled  +UA Infra: Extended Security Maintenance \(ESM\)
        fips         +yes      +<fips_status> +NIST-certified FIPS modules
        fips-updates +yes      +<fips_status> +Uncertified security updates to FIPS modules
        livepatch    +yes      +<lp_status>  +Canonical Livepatch service
        """
        And stderr matches regexp:
        """
        Enabling default service esm-infra
        """

        Examples: ubuntu release livepatch status
           | release | lp_status | fips_status |
           | xenial  | n/a       | n/a         |
           | bionic  | n/a       | disabled    |
           | focal   | n/a       | n/a         |

    @series.all
    @uses.config.machine_type.gcp.generic
    Scenario Outline: Attach command in a ubuntu lxd container
       Given a `<release>` machine with ubuntu-advantage-tools installed
        When I attach `contract_token` with sudo
        Then stdout matches regexp:
        """
        UA Infra: ESM enabled
        """
        And stdout matches regexp:
        """
        This machine is now attached to
        """
        And stdout matches regexp:
        """
        SERVICE       ENTITLED  STATUS    DESCRIPTION
        esm-infra    +yes      +enabled  +UA Infra: Extended Security Maintenance \(ESM\)
        fips         +yes      +<fips_status> +NIST-certified FIPS modules
        fips-updates +yes      +<fips_status> +Uncertified security updates to FIPS modules
        livepatch    +yes      +<lp_status>  +Canonical Livepatch service
        """
        And stderr matches regexp:
        """
        Enabling default service esm-infra
        """

        Examples: ubuntu release livepatch status
           | release | lp_status | fips_status |
           | xenial  | n/a       | n/a         |
           | bionic  | n/a       | n/a         |
           | focal   | n/a       | n/a         |

    @series.bionic
    @uses.config.machine_type.azure.generic
    Scenario Outline: Attached enable of vm-based services in an ubuntu lxd vm
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I attach `contract_token_staging` with sudo
        And I run `apt-get install openssh-client openssh-server strongswan -y` with sudo
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
        And I verify that running `apt update` `with sudo` exits `0`
        And I verify that running `grep Traceback /var/log/ubuntu-advantage.log` `with sudo` exits `1`
        And I verify that `openssh-server` is installed from apt source `<fips-apt-source>`
        And I verify that `openssh-client` is installed from apt source `<fips-apt-source>`
        And I verify that `strongswan` is installed from apt source `<fips-apt-source>`
        And I verify that `openssh-server-hmac` is installed from apt source `<fips-apt-source>`
        And I verify that `openssh-client-hmac` is installed from apt source `<fips-apt-source>`
        And I verify that `strongswan-hmac` is installed from apt source `<fips-apt-source>`
        When I run `apt-cache policy ubuntu-azure-fips` as non-root
        Then stdout does not match regexp:
        """
        .*Installed: \(none\)
        """
        When I reboot the `<release>` machine
        And  I run `uname -r` as non-root
        Then stdout matches regexp:
            """
            azure-fips
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
        """
        When I run `apt-cache policy ubuntu-azure-fips` as non-root
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

        Examples: ubuntu release
           | release | fips-name    | fips-service |fips-apt-source                                        |
           | bionic  | FIPS         | fips         |https://esm.staging.ubuntu.com/fips/ubuntu bionic/main |

    @series.bionic
    @uses.config.machine_type.aws.generic
    Scenario Outline: Attached enable of vm-based services in an ubuntu lxd vm
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I attach `contract_token_staging` with sudo
        And I run `ua disable livepatch` with sudo
        And I run `apt-get install openssh-client openssh-server strongswan -y` with sudo
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
        And I verify that running `apt update` `with sudo` exits `0`
        And I verify that running `grep Traceback /var/log/ubuntu-advantage.log` `with sudo` exits `1`
        And I verify that `openssh-server` is installed from apt source `<fips-apt-source>`
        And I verify that `openssh-client` is installed from apt source `<fips-apt-source>`
        And I verify that `strongswan` is installed from apt source `<fips-apt-source>`
        And I verify that `openssh-server-hmac` is installed from apt source `<fips-apt-source>`
        And I verify that `openssh-client-hmac` is installed from apt source `<fips-apt-source>`
        And I verify that `strongswan-hmac` is installed from apt source `<fips-apt-source>`
        When I run `apt-cache policy ubuntu-aws-fips` as non-root
        Then stdout does not match regexp:
        """
        .*Installed: \(none\)
        """
        When I reboot the `<release>` machine
        And  I run `uname -r` as non-root
        Then stdout matches regexp:
            """
            aws-fips
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
        """
        When I run `apt-cache policy ubuntu-aws-fips` as non-root
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

        Examples: ubuntu release
           | release | fips-name    | fips-service |fips-apt-source                                        |
           | bionic  | FIPS         | fips         |https://esm.staging.ubuntu.com/fips/ubuntu bionic/main |

    @series.xenial
    @uses.config.machine_type.azure.generic
    Scenario Outline: Attached enable of vm-based services in an ubuntu lxd vm
        Given a `xenial` machine with ubuntu-advantage-tools installed
        When I attach `contract_token_staging` with sudo
        Then I verify that running `ua enable <fips_service> --assume-yes` `with sudo` exits `1`
        And stdout matches regexp:
        """
        Ubuntu Xenial does not provide an Azure optimized FIPS kernel
        """

        Examples: fips
           | fips_service  |
           | fips          |
           | fips-updates  |

    @series.bionic
    @series.xenial
    @uses.config.machine_type.gcp.generic
    Scenario Outline: Attached enable of fips services in an ubuntu gcp vm
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I attach `contract_token_staging` with sudo
        Then I verify that running `ua enable <fips_service> --assume-yes` `with sudo` exits `1`
        And stdout matches regexp:
        """
        Ubuntu <release_title> does not provide a GCP optimized FIPS kernel
        """

        Examples: fips
            | release | release_title | fips_service  |
            | xenial  | Xenial        | fips          |
            | xenial  | Xenial        | fips-updates  |
            | bionic  | Bionic        | fips          |
            | bionic  | Bionic        | fips-updates  |
