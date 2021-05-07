from uaclient.entitlements import repo

try:
    from typing import Callable, Dict, List, Tuple, Union  # noqa
except ImportError:
    # typing isn't available on trusty, so ignore its absence
    pass

CIS_AUDIT_README = "/usr/share/doc/usg-common/README.audit.gz"
CIS_HARDENING_README = "/usr/share/doc/usg-cisbenchmark/README.hardening.gz"


class CISEntitlement(repo.RepoEntitlement):

    help_doc_url = "https://ubuntu.com/security/certifications#cis"
    name = "cis"
    title = "CIS Audit"
    description = "Center for Internet Security Audit Tools"
    repo_key_file = "ubuntu-advantage-cis.gpg"
    is_beta = True
    apt_noninteractive = True

    @property
    def messaging(
        self,
    ) -> "Dict[str, List[Union[str, Tuple[Callable, Dict]]]]":
        return {
            "post_enable": [
                "Refer to {} on how to run an audit scan of the system\n"
                "Refer to {} on how to harden the system to the desired CIS "
                "compliance level".format(
                    CIS_AUDIT_README, CIS_HARDENING_README
                )
            ]
        }
