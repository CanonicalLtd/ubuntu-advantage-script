# bash completion for ubuntu-advantage-tools

SERVICES=$(python3 -c "
from uaclient.entitlements import valid_services
print(*valid_services(), sep=' ')
")

_ua_complete()
{
    local cur_word prev_word
    cur_word="${COMP_WORDS[COMP_CWORD]}"
    prev_word="${COMP_WORDS[COMP_CWORD-1]}"

    subcmds=$(ua --help | awk '/^\s*$|Available|Use/ {next;} /Flags:/{flag=1;next}/Use ubuntu-avantage/{flag=0}flag{ if ( $1 ~ /,/ ) { print $2} else print $1}')
    base_params=""
    case ${COMP_CWORD} in
        1)
            COMPREPLY=($(compgen -W "$base_params $subcmds" -- $cur_word))
            ;;
        2)
            case ${prev_word} in
                disable)
                    COMPREPLY=($(compgen -W "$SERVICES" -- $cur_word))
                    ;;
                enable)
                    COMPREPLY=($(compgen -W "$SERVICES" -- $cur_word))
                    ;;
            esac
            ;;
        *)
            COMPREPLY=()
            ;;
    esac
}

complete -F _ua_complete ua

# vi: syntax=sh expandtab
