@uses.config.contract_token
Feature: Enable command behaviour when attached to an UA subscription

    @series.all
    Scenario Outline: Attached enable Common Criteria service in a ubuntu machine
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I attach `contract_token` with sudo
        Then I verify that running `ua enable cc-eal` `as non-root` exits `1`
        And I will see the following on stderr:
            """
            This command must be run as root (try using sudo).
            """
        And I verify that running `ua enable cc-eal --beta` `with sudo` exits `1`
        And I will see the following on stdout
            """
            One moment, checking your subscription first
            <msg>
            """
        And I verify that running `ua enable cc-eal` `with sudo` exits `1`
        And I will see the following on stdout:
            """
            One moment, checking your subscription first
            """
        And stderr matches regexp:
            """
            Cannot enable unknown service 'cc-eal'.
            Try esm-infra, fips, fips-updates, livepatch.
            """

        Examples: ubuntu release
           | release | msg                                                            |
           | bionic  | CC EAL2 is not available for Ubuntu 18.04 LTS (Bionic Beaver). |
           | focal   | CC EAL2 is not available for Ubuntu 20.04 LTS (Focal Fossa).   |
           | trusty  | CC EAL2 is not available for Ubuntu 14.04 LTS (Trusty Tahr).   |

    @series.all
    Scenario Outline: Attached enable of a service in a ubuntu machine
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I attach `contract_token` with sudo
        Then I verify that running `ua enable foobar` `as non-root` exits `1`
        And I will see the following on stderr:
            """
            This command must be run as root (try using sudo).
            """
        And I verify that running `ua enable foobar` `with sudo` exits `1`
        And I will see the following on stdout:
            """
            One moment, checking your subscription first
            """
        And stderr matches regexp:
            """
            Cannot enable unknown service 'foobar'.
            Try esm-infra, fips, fips-updates, livepatch.
            """
        And I verify that running `ua enable cc-eal foobar` `with sudo` exits `1`
        And I will see the following on stdout:
            """
            One moment, checking your subscription first
            """
        And stderr matches regexp:
            """
            Cannot enable unknown service 'foobar, cc-eal'.
            Try esm-infra, fips, fips-updates, livepatch.
            """
        And I verify that running `ua enable esm-infra` `with sudo` exits `1`
        Then I will see the following on stdout:
            """
            One moment, checking your subscription first
            UA Infra: ESM is already enabled.
            See: sudo ua status
            """
        When I run `apt-cache policy` with sudo
        Then apt-cache policy for the following url has permission `500`
        """
        <esm-infra-url> <release>-infra-updates/main amd64 Packages
        """
        And I verify that running `apt update` `with sudo` exits `0`
        When I run `apt install -y <infra-pkg>` with sudo, retrying exit [100]
        And I run `apt-cache policy <infra-pkg>` as non-root
        Then stdout matches regexp:
        """
        \s*500 <esm-infra-url> <release>-infra-security/main amd64 Packages
        \s*500 <esm-infra-url> <release>-infra-updates/main amd64 Packages
        """

        Examples: ubuntu release
           | release | infra-pkg | esm-infra-url                       |
           | bionic  | libkrad0  | https://esm.ubuntu.com/infra/ubuntu |
           | focal   | hello     | https://esm.ubuntu.com/infra/ubuntu |
           | trusty  | libgit2-0 | https://esm.ubuntu.com/ubuntu/      |
           | xenial  | libkrad0  | https://esm.ubuntu.com/infra/ubuntu |

    @series.all
    @uses.config.machine_type.lxd.container
    Scenario Outline:  Attached enable of non-container services in a ubuntu lxd container
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I attach `contract_token` with sudo
        Then I verify that running `ua enable livepatch` `as non-root` exits `1`
        And I will see the following on stderr:
            """
            This command must be run as root (try using sudo).
            """
        And I verify that running `ua enable livepatch` `with sudo` exits `1`
        And I will see the following on stdout:
            """
            One moment, checking your subscription first
            Cannot install Livepatch on a container.
            """
        And I verify that running `ua enable fips --assume-yes` `with sudo` exits `1`
        And I will see the following on stdout:
            """
            One moment, checking your subscription first
            Cannot install FIPS on a container.
            """
        And I verify that running `ua enable fips-updates --assume-yes` `with sudo` exits `1`
        And I will see the following on stdout:
            """
            One moment, checking your subscription first
            Cannot install FIPS Updates on a container.
            """

        Examples: Un-supported services in containers
           | release |
           | bionic  |
           | focal   |
           | trusty  |
           | xenial  |

    @series.all
    Scenario Outline: Attached enable not entitled service in a ubuntu machine
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I attach `contract_token` with sudo
        Then I verify that running `ua enable <service>` `as non-root` exits `1`
        And I will see the following on stderr:
            """
            This command must be run as root (try using sudo).
            """
        And I verify that running `ua enable cis --beta` `with sudo` exits `1`
        And I will see the following on stdout:
            """
            One moment, checking your subscription first
            This subscription is not entitled to CIS Audit
            For more information see: https://ubuntu.com/advantage.
            """
        And I verify that running `ua enable esm-apps` `with sudo` exits `1`
        And I will see the following on stdout:
            """
            One moment, checking your subscription first
            This subscription is not entitled to UA Apps: ESM
            For more information see: https://ubuntu.com/advantage.
            """

        Examples: not entitled services
           | release |
           | bionic  |
           | focal   |
           | trusty  |
           | xenial  |

    @series.focal
    @uses.config.machine_type.lxd.vm
    Scenario: Attached enable of vm-based services in a focal lxd vm
        Given a `focal` machine with ubuntu-advantage-tools installed
        When I attach `contract_token` with sudo
        Then I verify that running `ua enable fips --assume-yes` `with sudo` exits `1`
        And I will see the following on stdout:
            """
            One moment, checking your subscription first
            FIPS is not available for Ubuntu 20.04 LTS (Focal Fossa).
            """
        And I verify that running `ua enable fips-updates --assume-yes` `with sudo` exits `1`
        And I will see the following on stdout:
            """
            One moment, checking your subscription first
            FIPS Updates is not available for Ubuntu 20.04 LTS (Focal Fossa).
            """

    @series.bionic
    @series.xenial
    @uses.config.machine_type.lxd.vm
    Scenario Outline: Attached enable of vm-based services in a bionic lxd vm
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I attach `contract_token` with sudo
        And I run `ua status` with sudo
        Then stdout matches regexp:
        """
        esm-infra    +yes      +enabled  +UA Infra: Extended Security Maintenance \(ESM\)
        fips         +yes      +disabled +NIST-certified FIPS modules
        fips-updates +yes      +disabled +Uncertified security updates to FIPS modules
        livepatch    +yes      +enabled  +Canonical Livepatch service
        """
        When I run `ua disable livepatch` with sudo
        Then I verify that running `canonical-livepatch status` `with sudo` exits `1`
        And stdout matches regexp:
        """
        Machine is not enabled. Please run 'sudo canonical-livepatch enable' with the
        token obtained from https://ubuntu.com/livepatch.
        """
        When I run `ua status` with sudo
        Then stdout matches regexp:
        """
        esm-infra    +yes      +enabled  +UA Infra: Extended Security Maintenance \(ESM\)
        fips         +yes      +disabled +NIST-certified FIPS modules
        fips-updates +yes      +disabled +Uncertified security updates to FIPS modules
        livepatch    +yes      +disabled +Canonical Livepatch service
        """

        Examples: ubuntu release
           | release |
           | xenial  |
           | bionic  |

    @series.bionic
    @series.xenial
    @uses.config.machine_type.lxd.vm
    Scenario Outline: Attached enable livepatch on a machine with fips active
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I verify that running `canonical-livepatch status` `with sudo` exits `1`
        Then I will see the following on stderr:
            """
            sudo: canonical-livepatch: command not found
            """
        When I attach `contract_token` with sudo
        Then stdout matches regexp:
            """
            Installing canonical-livepatch snap
            Canonical livepatch enabled
            """
        When I run `ua status` with sudo
        Then stdout matches regexp:
            """
            livepatch     yes                enabled
            """
        When I run `canonical-livepatch status` with sudo
        Then stdout matches regexp:
            """
            running: true
            """

        Examples: ubuntu release
           | release |
           | xenial  |
           | bionic  |

    @series.bionic
    @uses.config.machine_type.lxd.vm
    Scenario: Attached enable fips on a machine with livepatch active
        Given a `bionic` machine with ubuntu-advantage-tools installed
        When I attach `contract_token` with sudo
        Then stdout matches regexp:
            """
            Updating package lists
            UA Infra: ESM enabled
            Installing canonical-livepatch snap
            Canonical livepatch enabled
            """
        When I run `ua disable livepatch` with sudo
        And I run `ua enable fips --assume-yes` with sudo
        Then I will see the following on stdout:
            """
            One moment, checking your subscription first
            Updating package lists
            Installing FIPS packages
            FIPS enabled
            A reboot is required to complete install.
            """
        When I append the following on uaclient config:
            """
            features:
              block_disable_on_enable: true
            """
        Then I verify that running `ua enable livepatch` `with sudo` exits `1`
        And I will see the following on stdout
            """
            One moment, checking your subscription first
            Cannot enable Livepatch when FIPS is enabled.
            """

    @series.bionic
    @uses.config.machine_type.lxd.vm
    Scenario: Attached enable livepatch on a machine with fips active
        Given a `bionic` machine with ubuntu-advantage-tools installed
        When I attach `contract_token` with sudo
        Then stdout matches regexp:
            """
            Updating package lists
            UA Infra: ESM enabled
            Installing canonical-livepatch snap
            Canonical livepatch enabled
            """
        When I append the following on uaclient config:
        """
        features:
          block_disable_on_enable: true
        """
        Then I verify that running `ua enable fips --assume-yes` `with sudo` exits `1`
        And I will see the following on stdout
            """
            One moment, checking your subscription first
            """
        And I will see the following on stderr
            """
            Cannot enable FIPS when Livepatch is enabled.
            """

    @series.xenial
    @series.bionic
    @uses.config.machine_type.lxd.vm
    Scenario Outline: Attached enable fips on a machine with livepatch active
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I attach `contract_token` with sudo
        Then stdout matches regexp:
            """
            Updating package lists
            UA Infra: ESM enabled
            """
        And stdout matches regexp:
            """
            Installing canonical-livepatch snap
            Canonical livepatch enabled
            """
        When I run `ua enable fips --assume-yes` with sudo
        Then I will see the following on stdout
            """
            One moment, checking your subscription first
            Updating package lists
            Installing FIPS packages
            FIPS enabled
            A reboot is required to complete install.
            """
        When I run `ua status` with sudo
        Then stdout matches regexp:
            """
            fips +yes +enabled
            """
        And stdout matches regexp:
            """
            livepatch +yes +n/a
            """

        Examples: ubuntu release
           | release |
           | bionic  |
           | xenial  |

    @series.xenial
    @series.bionic
    @uses.config.machine_type.lxd.vm
    Scenario Outline: Attached enable fips on a machine with fips-updates active
        Given a `<release>` machine with ubuntu-advantage-tools installed
        When I attach `contract_token` with sudo
        Then stdout matches regexp:
            """
            UA Infra: ESM enabled
            """
        And stdout matches regexp:
            """
            Installing canonical-livepatch snap
            Canonical livepatch enabled
            """
        When I run `ua disable livepatch` with sudo
        And I run `ua enable fips-updates --assume-yes` with sudo
        Then I will see the following on stdout:
            """
            One moment, checking your subscription first
            Updating package lists
            Installing FIPS Updates packages
            FIPS Updates enabled
            A reboot is required to complete install.
            """
        When I verify that running `ua enable fips --assume-yes` `with sudo` exits `1`
        Then I will see the following on stdout
            """
            One moment, checking your subscription first
            Cannot enable FIPS when FIPS Updates is enabled.
            """

        Examples: ubuntu release
           | release |
           | bionic  |
           | xenial  |
