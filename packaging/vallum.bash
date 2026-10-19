# bash completion for vallum
_vallum() {
    local cur prev commands
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"
    commands="run keygen pubkey genpsk show setconf addconf syncconf showconf bench doctor completions import-bundle tui help"

    if [[ ${COMP_CWORD} -eq 1 ]]; then
        COMPREPLY=( $(compgen -W "${commands}" -- "${cur}") )
        return 0
    fi
    case "${prev}" in
        --config|-c|--output|-o|--private-key|-k)
            COMPREPLY=( $(compgen -f -- "${cur}") )
            return 0
            ;;
        --control)
            COMPREPLY=( $(compgen -f -- "${cur}") )
            return 0
            ;;
        --suite)
            COMPREPLY=( $(compgen -W "1 2 3 0x0001 0x0002 0x0003" -- "${cur}") )
            return 0
            ;;
        completions)
            COMPREPLY=( $(compgen -W "bash zsh fish powershell" -- "${cur}") )
            return 0
            ;;
    esac
    if [[ "${cur}" == -* ]]; then
        COMPREPLY=( $(compgen -W "--config --control --dump --field --dry-run --help --version" -- "${cur}") )
    fi
}
complete -F _vallum vallum
complete -F _vallum vallum-quick
