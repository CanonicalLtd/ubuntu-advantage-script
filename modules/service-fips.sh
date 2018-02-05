# shellcheck disable=SC2034,SC2039

FIPS_SERVICE_TITLE="Canonical FIPS 140-2 Modules"
FIPS_SUPPORTED_SERIES="xenial"
FIPS_SUPPORTED_ARCHS="x86_64 ppc64le s390x"

FIPS_REPO_URL="private-ppa.launchpad.net/ubuntu-advantage/fips"
FIPS_REPO_KEY_FILE="ubuntu-fips-keyring.gpg"
FIPS_REPO_LIST=${FIPS_REPO_LIST:-"/etc/apt/sources.list.d/ubuntu-fips-${SERIES}.list"}
FIPS_UPDATES_REPO_URL="private-ppa.launchpad.net/ubuntu-advantage/fips-updates"
FIPS_UPDATES_REPO_KEY_FILE="ubuntu-fips-updates-keyring.gpg"
FIPS_UPDATES_REPO_LIST=${FIPS_UPDATES_REPO_LIST:-"/etc/apt/sources.list.d/ubuntu-fips-updates-${SERIES}.list"}
FIPS_ENABLED_FILE=${FIPS_ENABLED_FILE:-"/proc/sys/crypto/fips_enabled"}
if [ "$ARCH" = "s390x" ]; then
    FIPS_BOOT_CFG=${FIPS_BOOT_CFG:-"/etc/zipl.conf"}
else
    FIPS_BOOT_CFG_DIR=${FIPS_BOOT_CFG_DIR:-"/etc/default/grub.d"}
    FIPS_BOOT_CFG=${FIPS_BOOT_CFG:-"${FIPS_BOOT_CFG_DIR}/99-fips.cfg"}
fi
FIPS_HMAC_PACKAGES="openssh-client-hmac openssh-server-hmac libssl1.0.0-hmac \
        linux-fips strongswan-hmac"

fips_enable() {
    local token="$1"

    _fips_check_packages_installed || exit 6

    check_token "$FIPS_REPO_URL" "$token"
    apt_add_repo "$FIPS_REPO_LIST" "$FIPS_REPO_URL" "$token" \
                 "${KEYRINGS_DIR}/${FIPS_REPO_KEY_FILE}"
    install_package_if_missing_file "$APT_METHOD_HTTPS" apt-transport-https
    install_package_if_missing_file "$CA_CERTIFICATES" ca-certificates
    echo -n 'Running apt-get update... '
    check_result apt_get update
    echo 'Ubuntu FIPS PPA repository enabled.'

    # install all the fips packages
    echo -n 'Installing FIPS packages (this may take a while)... '
    _fips_install_packages

    echo "Configuring FIPS... "
    _fips_configure
    echo "Successfully configured FIPS. Please reboot into the FIPS kernel to enable it."
}

fips_update() {
    local token="$1"
    local bypass_prompt="$2"
    local fips_configured=0

    check_token "$FIPS_UPDATES_REPO_URL" "$token"

    echo -n "Updating FIPS packages will take the system out of FIPS compliance."
    if [ "$bypass_prompt" -ne 1 ]; then
        if ! prompt_user 'Do you want to proceed?'; then
            error_msg "Aborting updating FIPS packages..."
            exit 1
        fi
    fi

    #add the fips-updates repo if the system is undergoing updates the first time
    if [ ! -f "$FIPS_UPDATES_REPO_LIST" ]; then
        apt_add_repo "$FIPS_UPDATES_REPO_LIST" "$FIPS_UPDATES_REPO_URL" "$token" \
                 "${KEYRINGS_DIR}/${FIPS_UPDATES_REPO_KEY_FILE}"
        install_package_if_missing_file "$APT_METHOD_HTTPS" apt-transport-https
        install_package_if_missing_file "$CA_CERTIFICATES" ca-certificates
        echo -n 'Running apt-get update... '
        check_result apt_get update
        echo 'Ubuntu FIPS-UPDATES PPA repository enabled.'
    fi

    #if a fips package is found on the system, assume fips was configured before
    #users could be running with fips=0 or fips=1, so just checking package here
    if is_package_installed fips-initramfs; then
       fips_configured=1
    fi

    # update all the fips packages
    echo -n 'Updating FIPS packages (this may take a while)... '
    _fips_install_packages

    #if fips was configured before, just update the boot loader
    #if fips is enabled for the first time, configure fips
    if [ "$fips_configured" -eq 1 ]; then
        if [ "$ARCH" = "s390x" ]; then
            echo -n 'Updating zipl to enable updated fips kernel... '
            check_result zipl
        else
            echo -n 'Updating grub to enable updated fips kernel... '
            check_result update-grub
        fi
    else
        echo "Configuring FIPS... "
        _fips_configure
    fi
    echo "Successfully updated FIPS packages. Please reboot into the new FIPS kernel."
}

fips_is_enabled() {
    is_package_installed fips-initramfs && [ "$(_fips_enabled_check)" -eq 1 ]
}

fips_validate_token() {
    local token="$1"

    if ! validate_user_pass_token "$token"; then
        error_msg 'Invalid token, it must be in the form "user:password"'
        return 1
    fi
}

fips_check_support() {
    local power_cpu_ver
    case "$ARCH" in
        x86_64)
            if ! check_cpu_flag aes; then
                error_msg 'FIPS requires AES CPU extensions'
                return 7
            fi
            ;;

        ppc64le)
            power_cpu_ver="$(power_cpu_version)"
            if [ -z "$power_cpu_ver" ] || [ "$power_cpu_ver" -lt 8 ]; then
                error_msg 'FIPS requires POWER8 or later'
                return 7
            fi
            ;;
    esac
}

_fips_configure() {
    local bootdev fips_params result

    # if /boot has its own partition, then get the bootdevice
    # Note: /boot/efi  does not count
    bootdev=$(awk '!/^\s*#/ && $2 ~ /^\/boot\/?$/ { print $1 }' "$FSTAB")
    fips_params="fips=1"
    if [ -n "$bootdev" ]; then
        fips_params="$fips_params bootdev=$bootdev"
    fi

    if [ "$ARCH" = "s390x" ]; then
        sed -i -e 's,^parameters\s*=.*,& '"$fips_params"',' "$FIPS_BOOT_CFG"
        echo -n 'Updating zipl to enable fips... '
        check_result zipl
    else
        result=0
        if [ ! -d "$FIPS_BOOT_CFG_DIR" ]; then
            mkdir "$FIPS_BOOT_CFG_DIR" >/dev/null 2>&1 || result=$?
            if [ $result -ne 0 ]; then
                error_msg "Failed to make directory, $FIPS_BOOT_CFG_DIR."
                return 1
            fi
        fi
        echo "GRUB_CMDLINE_LINUX_DEFAULT=\"\$GRUB_CMDLINE_LINUX_DEFAULT $fips_params\"" >"$FIPS_BOOT_CFG"
        echo -n 'Updating grub to enable fips... '
        check_result update-grub
    fi
}

_fips_enabled_check() {
    if [ -f "$FIPS_ENABLED_FILE" ]; then
        cat "$FIPS_ENABLED_FILE"
        return
    fi
    echo 0
}

_fips_check_packages_installed() {
    local pkg
    for pkg in $FIPS_HMAC_PACKAGES; do
        if is_package_installed "$pkg"; then
            if fips_is_enabled; then
                error_msg "FIPS is already enabled."
            else
                error_msg "FIPS is already installed. Please reboot into the FIPS kernel to enable it."
            fi
            return 1
        fi
    done

    return 0
}

_fips_install_packages() {
    check_result apt_get install openssh-client openssh-client-hmac \
                 openssh-server openssh-server-hmac openssl libssl1.0.0 \
                 libssl1.0.0-hmac fips-initramfs linux-fips \
                 strongswan strongswan-hmac
}
