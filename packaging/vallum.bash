_vallum() {
    local i cur prev opts cmd
    COMPREPLY=()
    if [[ "${BASH_VERSINFO[0]}" -ge 4 ]]; then
        cur="$2"
    else
        cur="${COMP_WORDS[COMP_CWORD]}"
    fi
    prev="$3"
    cmd=""
    opts=""

    for i in "${COMP_WORDS[@]:0:COMP_CWORD}"
    do
        case "${cmd},${i}" in
            ",$1")
                cmd="vallum"
                ;;
            vallum,addconf)
                cmd="vallum__subcmd__addconf"
                ;;
            vallum,bench)
                cmd="vallum__subcmd__bench"
                ;;
            vallum,client)
                cmd="vallum__subcmd__client"
                ;;
            vallum,completions)
                cmd="vallum__subcmd__completions"
                ;;
            vallum,doctor)
                cmd="vallum__subcmd__doctor"
                ;;
            vallum,enroll-serve)
                cmd="vallum__subcmd__enroll__subcmd__serve"
                ;;
            vallum,genpsk)
                cmd="vallum__subcmd__genpsk"
                ;;
            vallum,help)
                cmd="vallum__subcmd__help"
                ;;
            vallum,identity)
                cmd="vallum__subcmd__identity"
                ;;
            vallum,import-bundle)
                cmd="vallum__subcmd__import__subcmd__bundle"
                ;;
            vallum,join)
                cmd="vallum__subcmd__join"
                ;;
            vallum,keygen)
                cmd="vallum__subcmd__keygen"
                ;;
            vallum,metrics)
                cmd="vallum__subcmd__metrics"
                ;;
            vallum,peer)
                cmd="vallum__subcmd__peer"
                ;;
            vallum,pubkey)
                cmd="vallum__subcmd__pubkey"
                ;;
            vallum,run)
                cmd="vallum__subcmd__run"
                ;;
            vallum,server)
                cmd="vallum__subcmd__server"
                ;;
            vallum,setconf)
                cmd="vallum__subcmd__setconf"
                ;;
            vallum,setup)
                cmd="vallum__subcmd__setup"
                ;;
            vallum,show)
                cmd="vallum__subcmd__show"
                ;;
            vallum,showconf)
                cmd="vallum__subcmd__showconf"
                ;;
            vallum,syncconf)
                cmd="vallum__subcmd__syncconf"
                ;;
            vallum,tui)
                cmd="vallum__subcmd__tui"
                ;;
            vallum__subcmd__client,help)
                cmd="vallum__subcmd__client__subcmd__help"
                ;;
            vallum__subcmd__client,teardown)
                cmd="vallum__subcmd__client__subcmd__teardown"
                ;;
            vallum__subcmd__client__subcmd__help,help)
                cmd="vallum__subcmd__client__subcmd__help__subcmd__help"
                ;;
            vallum__subcmd__client__subcmd__help,teardown)
                cmd="vallum__subcmd__client__subcmd__help__subcmd__teardown"
                ;;
            vallum__subcmd__help,addconf)
                cmd="vallum__subcmd__help__subcmd__addconf"
                ;;
            vallum__subcmd__help,bench)
                cmd="vallum__subcmd__help__subcmd__bench"
                ;;
            vallum__subcmd__help,client)
                cmd="vallum__subcmd__help__subcmd__client"
                ;;
            vallum__subcmd__help,completions)
                cmd="vallum__subcmd__help__subcmd__completions"
                ;;
            vallum__subcmd__help,doctor)
                cmd="vallum__subcmd__help__subcmd__doctor"
                ;;
            vallum__subcmd__help,enroll-serve)
                cmd="vallum__subcmd__help__subcmd__enroll__subcmd__serve"
                ;;
            vallum__subcmd__help,genpsk)
                cmd="vallum__subcmd__help__subcmd__genpsk"
                ;;
            vallum__subcmd__help,help)
                cmd="vallum__subcmd__help__subcmd__help"
                ;;
            vallum__subcmd__help,identity)
                cmd="vallum__subcmd__help__subcmd__identity"
                ;;
            vallum__subcmd__help,import-bundle)
                cmd="vallum__subcmd__help__subcmd__import__subcmd__bundle"
                ;;
            vallum__subcmd__help,join)
                cmd="vallum__subcmd__help__subcmd__join"
                ;;
            vallum__subcmd__help,keygen)
                cmd="vallum__subcmd__help__subcmd__keygen"
                ;;
            vallum__subcmd__help,metrics)
                cmd="vallum__subcmd__help__subcmd__metrics"
                ;;
            vallum__subcmd__help,peer)
                cmd="vallum__subcmd__help__subcmd__peer"
                ;;
            vallum__subcmd__help,pubkey)
                cmd="vallum__subcmd__help__subcmd__pubkey"
                ;;
            vallum__subcmd__help,run)
                cmd="vallum__subcmd__help__subcmd__run"
                ;;
            vallum__subcmd__help,server)
                cmd="vallum__subcmd__help__subcmd__server"
                ;;
            vallum__subcmd__help,setconf)
                cmd="vallum__subcmd__help__subcmd__setconf"
                ;;
            vallum__subcmd__help,setup)
                cmd="vallum__subcmd__help__subcmd__setup"
                ;;
            vallum__subcmd__help,show)
                cmd="vallum__subcmd__help__subcmd__show"
                ;;
            vallum__subcmd__help,showconf)
                cmd="vallum__subcmd__help__subcmd__showconf"
                ;;
            vallum__subcmd__help,syncconf)
                cmd="vallum__subcmd__help__subcmd__syncconf"
                ;;
            vallum__subcmd__help,tui)
                cmd="vallum__subcmd__help__subcmd__tui"
                ;;
            vallum__subcmd__help__subcmd__client,teardown)
                cmd="vallum__subcmd__help__subcmd__client__subcmd__teardown"
                ;;
            vallum__subcmd__help__subcmd__identity,issue)
                cmd="vallum__subcmd__help__subcmd__identity__subcmd__issue"
                ;;
            vallum__subcmd__help__subcmd__identity,self-sign)
                cmd="vallum__subcmd__help__subcmd__identity__subcmd__self__subcmd__sign"
                ;;
            vallum__subcmd__help__subcmd__identity,show)
                cmd="vallum__subcmd__help__subcmd__identity__subcmd__show"
                ;;
            vallum__subcmd__help__subcmd__identity,verify)
                cmd="vallum__subcmd__help__subcmd__identity__subcmd__verify"
                ;;
            vallum__subcmd__help__subcmd__peer,add)
                cmd="vallum__subcmd__help__subcmd__peer__subcmd__add"
                ;;
            vallum__subcmd__help__subcmd__peer,enroll)
                cmd="vallum__subcmd__help__subcmd__peer__subcmd__enroll"
                ;;
            vallum__subcmd__help__subcmd__peer,finalize)
                cmd="vallum__subcmd__help__subcmd__peer__subcmd__finalize"
                ;;
            vallum__subcmd__help__subcmd__peer,invite)
                cmd="vallum__subcmd__help__subcmd__peer__subcmd__invite"
                ;;
            vallum__subcmd__help__subcmd__peer,invites)
                cmd="vallum__subcmd__help__subcmd__peer__subcmd__invites"
                ;;
            vallum__subcmd__help__subcmd__peer,list)
                cmd="vallum__subcmd__help__subcmd__peer__subcmd__list"
                ;;
            vallum__subcmd__help__subcmd__peer,remove)
                cmd="vallum__subcmd__help__subcmd__peer__subcmd__remove"
                ;;
            vallum__subcmd__help__subcmd__peer,rotate)
                cmd="vallum__subcmd__help__subcmd__peer__subcmd__rotate"
                ;;
            vallum__subcmd__help__subcmd__peer,show)
                cmd="vallum__subcmd__help__subcmd__peer__subcmd__show"
                ;;
            vallum__subcmd__help__subcmd__server,enroll)
                cmd="vallum__subcmd__help__subcmd__server__subcmd__enroll"
                ;;
            vallum__subcmd__help__subcmd__server,init)
                cmd="vallum__subcmd__help__subcmd__server__subcmd__init"
                ;;
            vallum__subcmd__help__subcmd__server,teardown)
                cmd="vallum__subcmd__help__subcmd__server__subcmd__teardown"
                ;;
            vallum__subcmd__identity,help)
                cmd="vallum__subcmd__identity__subcmd__help"
                ;;
            vallum__subcmd__identity,issue)
                cmd="vallum__subcmd__identity__subcmd__issue"
                ;;
            vallum__subcmd__identity,self-sign)
                cmd="vallum__subcmd__identity__subcmd__self__subcmd__sign"
                ;;
            vallum__subcmd__identity,show)
                cmd="vallum__subcmd__identity__subcmd__show"
                ;;
            vallum__subcmd__identity,verify)
                cmd="vallum__subcmd__identity__subcmd__verify"
                ;;
            vallum__subcmd__identity__subcmd__help,help)
                cmd="vallum__subcmd__identity__subcmd__help__subcmd__help"
                ;;
            vallum__subcmd__identity__subcmd__help,issue)
                cmd="vallum__subcmd__identity__subcmd__help__subcmd__issue"
                ;;
            vallum__subcmd__identity__subcmd__help,self-sign)
                cmd="vallum__subcmd__identity__subcmd__help__subcmd__self__subcmd__sign"
                ;;
            vallum__subcmd__identity__subcmd__help,show)
                cmd="vallum__subcmd__identity__subcmd__help__subcmd__show"
                ;;
            vallum__subcmd__identity__subcmd__help,verify)
                cmd="vallum__subcmd__identity__subcmd__help__subcmd__verify"
                ;;
            vallum__subcmd__peer,add)
                cmd="vallum__subcmd__peer__subcmd__add"
                ;;
            vallum__subcmd__peer,enroll)
                cmd="vallum__subcmd__peer__subcmd__enroll"
                ;;
            vallum__subcmd__peer,finalize)
                cmd="vallum__subcmd__peer__subcmd__finalize"
                ;;
            vallum__subcmd__peer,help)
                cmd="vallum__subcmd__peer__subcmd__help"
                ;;
            vallum__subcmd__peer,invite)
                cmd="vallum__subcmd__peer__subcmd__invite"
                ;;
            vallum__subcmd__peer,invites)
                cmd="vallum__subcmd__peer__subcmd__invites"
                ;;
            vallum__subcmd__peer,list)
                cmd="vallum__subcmd__peer__subcmd__list"
                ;;
            vallum__subcmd__peer,remove)
                cmd="vallum__subcmd__peer__subcmd__remove"
                ;;
            vallum__subcmd__peer,rotate)
                cmd="vallum__subcmd__peer__subcmd__rotate"
                ;;
            vallum__subcmd__peer,show)
                cmd="vallum__subcmd__peer__subcmd__show"
                ;;
            vallum__subcmd__peer__subcmd__help,add)
                cmd="vallum__subcmd__peer__subcmd__help__subcmd__add"
                ;;
            vallum__subcmd__peer__subcmd__help,enroll)
                cmd="vallum__subcmd__peer__subcmd__help__subcmd__enroll"
                ;;
            vallum__subcmd__peer__subcmd__help,finalize)
                cmd="vallum__subcmd__peer__subcmd__help__subcmd__finalize"
                ;;
            vallum__subcmd__peer__subcmd__help,help)
                cmd="vallum__subcmd__peer__subcmd__help__subcmd__help"
                ;;
            vallum__subcmd__peer__subcmd__help,invite)
                cmd="vallum__subcmd__peer__subcmd__help__subcmd__invite"
                ;;
            vallum__subcmd__peer__subcmd__help,invites)
                cmd="vallum__subcmd__peer__subcmd__help__subcmd__invites"
                ;;
            vallum__subcmd__peer__subcmd__help,list)
                cmd="vallum__subcmd__peer__subcmd__help__subcmd__list"
                ;;
            vallum__subcmd__peer__subcmd__help,remove)
                cmd="vallum__subcmd__peer__subcmd__help__subcmd__remove"
                ;;
            vallum__subcmd__peer__subcmd__help,rotate)
                cmd="vallum__subcmd__peer__subcmd__help__subcmd__rotate"
                ;;
            vallum__subcmd__peer__subcmd__help,show)
                cmd="vallum__subcmd__peer__subcmd__help__subcmd__show"
                ;;
            vallum__subcmd__server,enroll)
                cmd="vallum__subcmd__server__subcmd__enroll"
                ;;
            vallum__subcmd__server,help)
                cmd="vallum__subcmd__server__subcmd__help"
                ;;
            vallum__subcmd__server,init)
                cmd="vallum__subcmd__server__subcmd__init"
                ;;
            vallum__subcmd__server,teardown)
                cmd="vallum__subcmd__server__subcmd__teardown"
                ;;
            vallum__subcmd__server__subcmd__help,enroll)
                cmd="vallum__subcmd__server__subcmd__help__subcmd__enroll"
                ;;
            vallum__subcmd__server__subcmd__help,help)
                cmd="vallum__subcmd__server__subcmd__help__subcmd__help"
                ;;
            vallum__subcmd__server__subcmd__help,init)
                cmd="vallum__subcmd__server__subcmd__help__subcmd__init"
                ;;
            vallum__subcmd__server__subcmd__help,teardown)
                cmd="vallum__subcmd__server__subcmd__help__subcmd__teardown"
                ;;
            *)
                ;;
        esac
    done

    case "${cmd}" in
        vallum)
            opts="-h -V --allow-insecure-key-permissions --help --version setup run keygen pubkey genpsk show setconf addconf syncconf showconf bench doctor server client join peer metrics identity import-bundle enroll-serve tui completions help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 1 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__addconf)
            opts="-h --control --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --control)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__bench)
            opts="-h --suite --bytes --iterations --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --suite)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --bytes)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --iterations)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__client)
            opts="-h --allow-insecure-key-permissions --help teardown help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__client__subcmd__help)
            opts="teardown help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__client__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__client__subcmd__help__subcmd__teardown)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__client__subcmd__teardown)
            opts="-h --config --name --purge --dry-run --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__completions)
            opts="-h --allow-insecure-key-permissions --help bash elvish fish powershell zsh"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__doctor)
            opts="-c -h --config --control --probe-mtu --json --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --control)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --probe-mtu)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__enroll__subcmd__serve)
            opts="-h --config --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__genpsk)
            opts="-h --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help)
            opts="setup run keygen pubkey genpsk show setconf addconf syncconf showconf bench doctor server client join peer metrics identity import-bundle enroll-serve tui completions help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__addconf)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__bench)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__client)
            opts="teardown"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__client__subcmd__teardown)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__completions)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__doctor)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__enroll__subcmd__serve)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__genpsk)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__identity)
            opts="issue self-sign verify show"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__identity__subcmd__issue)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__identity__subcmd__self__subcmd__sign)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__identity__subcmd__show)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__identity__subcmd__verify)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__import__subcmd__bundle)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__join)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__keygen)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__metrics)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__peer)
            opts="add list show remove enroll invite invites rotate finalize"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__peer__subcmd__add)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__peer__subcmd__enroll)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__peer__subcmd__finalize)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__peer__subcmd__invite)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__peer__subcmd__invites)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__peer__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__peer__subcmd__remove)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__peer__subcmd__rotate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__peer__subcmd__show)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__pubkey)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__run)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__server)
            opts="init enroll teardown"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__server__subcmd__enroll)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__server__subcmd__init)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__server__subcmd__teardown)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__setconf)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__setup)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__show)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__showconf)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__syncconf)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__help__subcmd__tui)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__identity)
            opts="-h --allow-insecure-key-permissions --help issue self-sign verify show help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__identity__subcmd__help)
            opts="issue self-sign verify show help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__identity__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__identity__subcmd__help__subcmd__issue)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__identity__subcmd__help__subcmd__self__subcmd__sign)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__identity__subcmd__help__subcmd__show)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__identity__subcmd__help__subcmd__verify)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__identity__subcmd__issue)
            opts="-h --ca-key --peer-public --peer-public-file --label --days --not-before --output --json --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --ca-key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --peer-public)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --peer-public-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --label)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --days)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --not-before)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__identity__subcmd__self__subcmd__sign)
            opts="-h --key --label --days --not-before --output --json --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --label)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --days)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --not-before)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__identity__subcmd__show)
            opts="-h --document --suite --json --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --document)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --suite)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__identity__subcmd__verify)
            opts="-h --issuer --issuer-public --document --suite --json --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --issuer)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --issuer-public)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --document)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --suite)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__import__subcmd__bundle)
            opts="-h --output-dir --force --install --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__join)
            opts="-h --name --dry-run --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__keygen)
            opts="-o -h --output --suite --signing --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -o)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --suite)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__metrics)
            opts="-c -h --config --control --prefix --output --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --control)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --prefix)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --output)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__peer)
            opts="-h --allow-insecure-key-permissions --help add list show remove enroll invite invites rotate finalize help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__peer__subcmd__add)
            opts="-h --config --public-key --public-key-file --bundle-out --ship-key --client-config-out --identity --address --allowed-ips --endpoint --keepalive --pin-endpoint --psk --dns --forget-key --no-apply --json --full --quiet --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --public-key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --public-key-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --bundle-out)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --client-config-out)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --identity)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --address)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --allowed-ips)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --endpoint)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keepalive)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dns)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__peer__subcmd__enroll)
            opts="-h --config --public-key --public-key-file --address --keepalive --no-apply --json --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --public-key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --public-key-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --address)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keepalive)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__peer__subcmd__finalize)
            opts="-h --config --no-apply --json --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__peer__subcmd__help)
            opts="add list show remove enroll invite invites rotate finalize help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__peer__subcmd__help__subcmd__add)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__peer__subcmd__help__subcmd__enroll)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__peer__subcmd__help__subcmd__finalize)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__peer__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__peer__subcmd__help__subcmd__invite)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__peer__subcmd__help__subcmd__invites)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__peer__subcmd__help__subcmd__list)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__peer__subcmd__help__subcmd__remove)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__peer__subcmd__help__subcmd__rotate)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__peer__subcmd__help__subcmd__show)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__peer__subcmd__invite)
            opts="-h --config --public-key --public-key-file --ttl --json --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --public-key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --public-key-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --ttl)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__peer__subcmd__invites)
            opts="-h --config --json --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__peer__subcmd__list)
            opts="-h --config --full --json --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__peer__subcmd__remove)
            opts="-h --config --no-apply --json --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__peer__subcmd__rotate)
            opts="-h --config --public-key --public-key-file --bundle-out --ship-key --identity --endpoint --dns --forget-key --no-apply --json --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --public-key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --public-key-file)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --bundle-out)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --identity)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --endpoint)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dns)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__peer__subcmd__show)
            opts="-h --config --full --json --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__pubkey)
            opts="-k -h --private-key --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --private-key)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -k)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__run)
            opts="-c -h --config --tick-ms --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --tick-ms)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__server)
            opts="-h --allow-insecure-key-permissions --help init enroll teardown help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__server__subcmd__enroll)
            opts="-h --config --enable --disable --dry-run --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__server__subcmd__help)
            opts="init enroll teardown help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__server__subcmd__help__subcmd__enroll)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__server__subcmd__help__subcmd__help)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__server__subcmd__help__subcmd__init)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__server__subcmd__help__subcmd__teardown)
            opts=""
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 4 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__server__subcmd__init)
            opts="-h --config --name --address --listen --endpoint --control --enroll --dns --user --no-nat --no-firewall --no-forward --no-service --no-host --dry-run --force --json --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --address)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --listen)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --endpoint)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --control)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --dns)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --user)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__server__subcmd__teardown)
            opts="-h --config --purge --dry-run --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 3 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__setconf)
            opts="-h --control --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --control)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__setup)
            opts="-h --server --client --yes --endpoint --address --listen --name --remote --remote-config --join --token --invite-id --expect --enroll --dry-run --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --client)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --endpoint)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --address)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --listen)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --name)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --remote)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --remote-config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --join)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --token)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --invite-id)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --expect)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__show)
            opts="-c -h --config --control --dump --json --watch --interval --field --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --control)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --interval)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --field)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__showconf)
            opts="-c -h --config --control --include-secrets --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --control)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__syncconf)
            opts="-h --control --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --control)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
        vallum__subcmd__tui)
            opts="-c -h --config --control --config-dir --snapshot --width --height --ansi --snapshot-view --keys --allow-insecure-key-permissions --help"
            if [[ ${cur} == -* || ${COMP_CWORD} -eq 2 ]] ; then
                COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
                return 0
            fi
            case "${prev}" in
                --config)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                -c)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --control)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --config-dir)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --width)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --height)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --snapshot-view)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                --keys)
                    COMPREPLY=($(compgen -f "${cur}"))
                    return 0
                    ;;
                *)
                    COMPREPLY=()
                    ;;
            esac
            COMPREPLY=( $(compgen -W "${opts}" -- "${cur}") )
            return 0
            ;;
    esac
}

if [[ "${BASH_VERSINFO[0]}" -eq 4 && "${BASH_VERSINFO[1]}" -ge 4 || "${BASH_VERSINFO[0]}" -gt 4 ]]; then
    complete -F _vallum -o nosort -o bashdefault -o default vallum
else
    complete -F _vallum -o bashdefault -o default vallum
fi
