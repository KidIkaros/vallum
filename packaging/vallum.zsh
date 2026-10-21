#compdef vallum

autoload -U is-at-least

_vallum() {
    typeset -A opt_args
    typeset -a _arguments_options
    local ret=1

    if is-at-least 5.2; then
        _arguments_options=(-s -S -C)
    else
        _arguments_options=(-s -C)
    fi

    local context curcontext="$curcontext" state line
    _arguments "${_arguments_options[@]}" : \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
'-V[Print version]' \
'--version[Print version]' \
":: :_vallum_commands" \
"*::: :->vallum" \
&& ret=0
    case $state in
    (vallum)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:vallum-command-$line[1]:"
        case $line[1] in
            (setup)
_arguments "${_arguments_options[@]}" : \
'(--server)--client=[This machine connects to a server, from a \`.vallum-bundle\` file]:BUNDLE:_files' \
'--endpoint=[The address clients dial. Detected when absent]:HOST:PORT:_default' \
'--address=[The tunnel address and prefix]:CIDR:_default' \
'--listen=[The UDP address to listen on]:ADDR:PORT:_default' \
'--name=[The instance name\: the config file stem and the unit instance]:NAME:_default' \
'(--server --client --join --token)--remote=[Enrol this machine against a server over SSH, which needs no bundle and never sends this machine'\''s private key anywhere]:USER@HOST:_default' \
'--remote-config=[The server config to edit when enrolling with \`--remote\` (for a server whose instance is not \`vallum0\`)]:FILE:_files' \
'(--server --client --remote)--join=[Enrol with a single-use token, for machines that cannot SSH to the server. Takes the \`vallum1-join\:…\` ticket \`vallum peer invite\` prints, or a bare \`host\:port\` together with --invite-id and --token]:TICKET|HOST:PORT:_default' \
'--token=[The single-use token from \`vallum peer invite\`, or \`-\` to read it from stdin so it stays out of shell history and \`ps\`]:TOKEN:_default' \
'--invite-id=[The invite id from \`vallum peer invite\` (32 hex characters)]:HEX:_default' \
'--expect=[Refuse the answer unless the server'\''s fingerprint matches this. Printed by \`vallum peer invite\`; it is how a client knows it reached the right server rather than one that answered first]:FINGERPRINT:_default' \
'(--client)--server[This machine accepts clients]' \
'--yes[Take the defaults and the host changes without asking]' \
'--enroll[On a server, allow devices to enrol with a one-time token (opens UDP \`listen + 1\`)]' \
'--dry-run[Print every step and change nothing]' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(run)
_arguments "${_arguments_options[@]}" : \
'-c+[The configuration file]:FILE:_files' \
'--config=[The configuration file]:FILE:_files' \
'--tick-ms=[How often the loop wakes with nothing to do, in milliseconds]:MS:_default' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(keygen)
_arguments "${_arguments_options[@]}" : \
'-o+[Where to write the private key. Refuses to overwrite an existing file]:FILE:_files' \
'--output=[Where to write the private key. Refuses to overwrite an existing file]:FILE:_files' \
'--suite=[The suite id, decimal or \`0x\`-prefixed hex. Defaults to the tri-hybrid]:ID:_default' \
'--signing[Also derive a hybrid signing key pair, turning on P3 identity]' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(pubkey)
_arguments "${_arguments_options[@]}" : \
'-k+[The private key to read]:FILE:_files' \
'--private-key=[The private key to read]:FILE:_files' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(genpsk)
_arguments "${_arguments_options[@]}" : \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(show)
_arguments "${_arguments_options[@]}" : \
'-c+[The configuration file, for its \`control\` path]:FILE:_files' \
'--config=[The configuration file, for its \`control\` path]:FILE:_files' \
'--control=[The control socket path, instead of a config]:SOCKET:_files' \
'--interval=[Refresh interval for \`--watch\`, in milliseconds]:MS:_default' \
'--field=[Print only one field (endpoints, allowed-ips, transfer, ...)]:FIELD:_default' \
'--dump[Print the raw UAPI response]' \
'--json[Emit the secret-free JSON view]' \
'--watch[Refresh the view until Ctrl-C]' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(setconf)
_arguments "${_arguments_options[@]}" : \
'--control=[The control socket path, instead of the config'\''s \`control\` field]:SOCKET:_files' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':config -- The configuration file to apply:_files' \
&& ret=0
;;
(addconf)
_arguments "${_arguments_options[@]}" : \
'--control=[The control socket path, instead of the config'\''s \`control\` field]:SOCKET:_files' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':config -- The configuration file to apply:_files' \
&& ret=0
;;
(syncconf)
_arguments "${_arguments_options[@]}" : \
'--control=[The control socket path, instead of the config'\''s \`control\` field]:SOCKET:_files' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':config -- The configuration file to apply:_files' \
&& ret=0
;;
(showconf)
_arguments "${_arguments_options[@]}" : \
'-c+[The configuration file, for its \`control\` path]:FILE:_files' \
'--config=[The configuration file, for its \`control\` path]:FILE:_files' \
'--control=[The control socket path, instead of a config]:SOCKET:_files' \
'--include-secrets[Include the private-key path and preshared keys in the export]' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(bench)
_arguments "${_arguments_options[@]}" : \
'--suite=[The suite id, decimal or \`0x\`-prefixed hex. Defaults to the tri-hybrid]:ID:_default' \
'--bytes=[Payload size in bytes]:BYTES:_default' \
'--iterations=[Iterations to time]:N:_default' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(doctor)
_arguments "${_arguments_options[@]}" : \
'-c+[The configuration file to check]:FILE:_files' \
'--config=[The configuration file to check]:FILE:_files' \
'--control=[The control socket to query, instead of the config'\''s \`control\`]:SOCKET:_files' \
'--probe-mtu=[Probe the path MTU to this host with \`ping -M do\` and compare it with the config'\''s \`outer_mtu\`]:HOST:_default' \
'--json[Emit JSON instead of a table]' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(server)
_arguments "${_arguments_options[@]}" : \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_vallum__subcmd__server_commands" \
"*::: :->server" \
&& ret=0

    case $state in
    (server)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:vallum-server-command-$line[1]:"
        case $line[1] in
            (init)
_arguments "${_arguments_options[@]}" : \
'--config=[The configuration file to write]:FILE:_files' \
'--name=[The kernel interface name. Defaults to the config file'\''s stem]:NAME:_default' \
'*--address=[The address and prefix for the interface. Repeat for dual-stack]:CIDR:_default' \
'--listen=[The UDP address to listen on]:ADDR:PORT:_default' \
'--endpoint=[The address clients dial, printed in their bundles. Detected if absent]:HOST:PORT:_default' \
'--control=[The control socket path. Defaults to /run/vallum/<name>.sock]:PATH:_files' \
'*--dns=[A DNS server to push to clients through \`\[quick\]\`. Repeatable]:ADDR:_default' \
'--user=[The user to drop to after the interface and socket are open]:USER:_default' \
'--enroll[Allow devices to enrol with a one-time token, which opens UDP \`listen + 1\` and enables the \`vallum-enroll@\` unit]' \
'--no-nat[Do not install the masquerade rule]' \
'--no-firewall[Do not open the UDP port in the host firewall]' \
'--no-forward[Do not enable IP forwarding]' \
'--no-service[Do not install or start the systemd units]' \
'--no-host[Do not change anything about the host (implies the three \`--no-*\` above)]' \
'--dry-run[Print every step and change nothing]' \
'--force[Rewrite an existing config (the key is never regenerated)]' \
'--json[Emit JSON instead of a report]' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(enroll)
_arguments "${_arguments_options[@]}" : \
'--config=[The configuration file to change]:FILE:_files' \
'(--disable)--enable[Allow devices to enrol with a one-time token]' \
'--disable[Stop answering enrolment requests, and try to close the port]' \
'--dry-run[Show what would change, without changing it]' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(teardown)
_arguments "${_arguments_options[@]}" : \
'--config=[The server configuration file to tear down]:FILE:_files' \
'--purge[Also delete the config file and keys in \`/etc/vallum\`. Without this, they stay in place so \`server init\` can bring the same server back up]' \
'--dry-run[Show what would be removed, without changing the host]' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_vallum__subcmd__server__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:vallum-server-help-command-$line[1]:"
        case $line[1] in
            (init)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(enroll)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(teardown)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(client)
_arguments "${_arguments_options[@]}" : \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_vallum__subcmd__client_commands" \
"*::: :->client" \
&& ret=0

    case $state in
    (client)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:vallum-client-command-$line[1]:"
        case $line[1] in
            (teardown)
_arguments "${_arguments_options[@]}" : \
'--config=[The client configuration file to tear down]:FILE:_files' \
'(--config)--name=[The client name — resolves to \`/etc/vallum/<name>.toml\`]:NAME:_default' \
'--purge[Also delete the config file and key in \`/etc/vallum\`. Without this, they stay in place so the tunnel can be brought back up]' \
'--dry-run[Show what would be removed, without changing the host]' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_vallum__subcmd__client__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:vallum-client-help-command-$line[1]:"
        case $line[1] in
            (teardown)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(join)
_arguments "${_arguments_options[@]}" : \
'--name=[The name this machine'\''s config files take. Defaults to the name the invite was minted for]:NAME:_default' \
'--dry-run[Print every step and change nothing]' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':ticket -- The `vallum1-join\:…` ticket `vallum peer invite` printed on the server. It carries the responder address, invite id, token, and server fingerprint in one string — there are no other flags to get right:_default' \
&& ret=0
;;
(peer)
_arguments "${_arguments_options[@]}" : \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_vallum__subcmd__peer_commands" \
"*::: :->peer" \
&& ret=0

    case $state in
    (peer)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:vallum-peer-command-$line[1]:"
        case $line[1] in
            (add)
_arguments "${_arguments_options[@]}" : \
'--config=[The configuration file to edit]:FILE:_files' \
'(--public-key-file --bundle-out)--public-key=[The peer'\''s public line (the device generated its own key)]:LINE:_default' \
'(--public-key --bundle-out)--public-key-file=[A file holding the peer'\''s public line]:FILE:_files' \
'(--public-key --public-key-file)--bundle-out=[Generate the keypair here and write the client'\''s bundle to this path]:FILE:_files' \
'(--bundle-out)--client-config-out=[Write the client'\''s config to this path (no private key\: the device has its own). Use with \`--public-key\`]:FILE:_files' \
'(--public-key --public-key-file --bundle-out)--identity=[Enrol a peer by its identity document instead of a public line]:FILE:_files' \
'--address=[The address to route to the peer. Allocated if absent]:CIDR:_default' \
'--allowed-ips=[The prefixes routed to the peer. Defaults to the peer'\''s address]:LIST:_default' \
'--endpoint=[The address the client dials. Detected for a bundle if absent]:HOST:PORT:_default' \
'--keepalive=[Send a keepalive every this many seconds]:SECS:_default' \
'*--dns=[A DNS server to push to the client bundle. Repeatable]:ADDR:_default' \
'--ship-key[Confirm that this server should generate the device'\''s key and hand it over. Only for devices that cannot generate their own]' \
'--pin-endpoint[Refuse handshakes from any address other than \`--endpoint\`]' \
'--psk[Generate a preshared key and store it next to the config]' \
'--forget-key[Delete the server'\''s copy of the client key after writing the bundle]' \
'--no-apply[Write the config but do not tell a running daemon]' \
'--json[Emit JSON instead of a report]' \
'--full[Include the full public line in JSON output]' \
'--quiet[Suppress the report. Used by \`peer enroll\`, which prints its own]' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':name -- The peer'\''s name, as it appears in logs and in the file:_default' \
&& ret=0
;;
(list)
_arguments "${_arguments_options[@]}" : \
'--config=[The configuration file to read]:FILE:_files' \
'--full[Include the full public line, not just its fingerprint]' \
'--json[Emit JSON instead of a table]' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(show)
_arguments "${_arguments_options[@]}" : \
'--config=[The configuration file to read]:FILE:_files' \
'--full[Print the full public line]' \
'--json[Emit JSON instead of a report]' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':name -- The peer'\''s name:_default' \
&& ret=0
;;
(remove)
_arguments "${_arguments_options[@]}" : \
'--config=[The configuration file to edit]:FILE:_files' \
'--no-apply[Write the config but do not tell a running daemon]' \
'--json[Emit JSON instead of a report]' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':name -- The peer'\''s name:_default' \
&& ret=0
;;
(enroll)
_arguments "${_arguments_options[@]}" : \
'--config=[The configuration file to edit]:FILE:_files' \
'(--public-key-file)--public-key=[The device'\''s public line, generated on the device itself]:LINE:_default' \
'--public-key-file=[A file holding the device'\''s public line]:FILE:_files' \
'--address=[The address to route to the device. Allocated if absent]:CIDR:_default' \
'--keepalive=[Send a keepalive every this many seconds]:SECS:_default' \
'--no-apply[Write the config but do not tell a running daemon]' \
'--json[Emit JSON instead of a report]' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':name -- The name this device will have on the server:_default' \
&& ret=0
;;
(invite)
_arguments "${_arguments_options[@]}" : \
'--config=[The configuration file this invite is for]:FILE:_files' \
'(--public-key-file)--public-key=[Bind the invite to the device'\''s public line\: a stolen token then enrols nothing, because the attacker has no matching private key]:LINE:_default' \
'--public-key-file=[A file holding the device'\''s public line]:FILE:_files' \
'--ttl=[How long the invite lives, in minutes]:MINUTES:_default' \
'--json[Emit JSON instead of a report]' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':name -- The name the device will enrol under:_default' \
&& ret=0
;;
(invites)
_arguments "${_arguments_options[@]}" : \
'--config=[The configuration file whose interface to inspect]:FILE:_files' \
'--json[Emit JSON instead of a table (tokens are never printed here)]' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(rotate)
_arguments "${_arguments_options[@]}" : \
'--config=[The configuration file to edit]:FILE:_files' \
'(--public-key-file --bundle-out --identity)--public-key=[The peer'\''s new public line]:LINE:_default' \
'(--public-key --bundle-out --identity)--public-key-file=[A file holding the new public line]:FILE:_files' \
'(--public-key --public-key-file --identity)--bundle-out=[Generate the new keypair here and write the client'\''s bundle]:FILE:_files' \
'(--public-key --public-key-file --bundle-out)--identity=[The peer'\''s new identity document]:FILE:_files' \
'--endpoint=[The address the client dials, for the bundle. Detected if absent]:HOST:PORT:_default' \
'*--dns=[A DNS server to push to the client bundle. Repeatable]:ADDR:_default' \
'--ship-key[Confirm that this server should generate the replacement key]' \
'--forget-key[Delete the server'\''s copy of the generated key after writing the bundle]' \
'--no-apply[Write the config but do not tell a running daemon]' \
'--json[Emit JSON instead of a report]' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':name -- The peer to rotate:_default' \
&& ret=0
;;
(finalize)
_arguments "${_arguments_options[@]}" : \
'--config=[The configuration file to edit]:FILE:_files' \
'--no-apply[Write the config but do not tell a running daemon]' \
'--json[Emit JSON instead of a report]' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':name -- The peer whose previous identity should be retired:_default' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_vallum__subcmd__peer__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:vallum-peer-help-command-$line[1]:"
        case $line[1] in
            (add)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(list)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(show)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(remove)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(enroll)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(invite)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(invites)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(rotate)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(finalize)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(metrics)
_arguments "${_arguments_options[@]}" : \
'-c+[The configuration file, for its \`control\` path]:FILE:_files' \
'--config=[The configuration file, for its \`control\` path]:FILE:_files' \
'--control=[The control socket path, instead of a config]:SOCKET:_files' \
'--prefix=[The metric name prefix]:PREFIX:_default' \
'--output=[Write the exposition to a file instead of stdout]:FILE:_files' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(identity)
_arguments "${_arguments_options[@]}" : \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
":: :_vallum__subcmd__identity_commands" \
"*::: :->identity" \
&& ret=0

    case $state in
    (identity)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:vallum-identity-command-$line[1]:"
        case $line[1] in
            (issue)
_arguments "${_arguments_options[@]}" : \
'--ca-key=[The CA key, which must carry a signing half (\`keygen --signing\`)]:FILE:_files' \
'(--peer-public-file)--peer-public=[The peer'\''s public line, which must carry a signing key]:LINE:_default' \
'--peer-public-file=[A file holding the peer'\''s public line]:FILE:_files' \
'--label=[A name for the document, for logs and \`peer show\`]:NAME:_default' \
'--days=[How long the document is valid, in days]:DAYS:_default' \
'--not-before=[The first second the document is valid. Defaults to now]:UNIX:_default' \
'--output=[Write the document here (0600) instead of stdout]:FILE:_files' \
'--json[Emit JSON instead of the document text]' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(self-sign)
_arguments "${_arguments_options[@]}" : \
'--key=[The peer'\''s own key, which must carry a signing half]:FILE:_files' \
'--label=[A name for the document]:NAME:_default' \
'--days=[How long the document is valid, in days]:DAYS:_default' \
'--not-before=[The first second the document is valid. Defaults to now]:UNIX:_default' \
'--output=[Write the document here (0600) instead of stdout]:FILE:_files' \
'--json[Emit JSON instead of the document text]' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(verify)
_arguments "${_arguments_options[@]}" : \
'(--issuer-public)--issuer=[A file holding the issuer'\''s \`vallum1\:\` public line — what \`vallum keygen\` prints. Verification never needs the CA'\''s private key]:FILE:_files' \
'--issuer-public=[The issuer'\''s public line, instead of a file]:LINE:_default' \
'--document=[The document to check]:FILE:_files' \
'--suite=[The suite to verify a self-signed document with]:ID:_default' \
'--json[Emit JSON instead of a report]' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(show)
_arguments "${_arguments_options[@]}" : \
'--document=[The document to inspect]:FILE:_files' \
'--suite=[The suite the document was encoded under]:ID:_default' \
'--json[Emit JSON instead of a report]' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_vallum__subcmd__identity__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:vallum-identity-help-command-$line[1]:"
        case $line[1] in
            (issue)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(self-sign)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(verify)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(show)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
;;
(import-bundle)
_arguments "${_arguments_options[@]}" : \
'--output-dir=[Directory for the config and key (default\: /etc/vallum with --install, the current directory otherwise)]:DIR:_files' \
'--force[Overwrite an existing config or key]' \
'--install[Install to /etc/vallum, install the units, and start the tunnel]' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':bundle -- The `.vallum-bundle` file to import:_files' \
&& ret=0
;;
(enroll-serve)
_arguments "${_arguments_options[@]}" : \
'--config=[The configuration file whose \`\[enroll\]\` section governs the responder]:FILE:_files' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(tui)
_arguments "${_arguments_options[@]}" : \
'-c+[A configuration file to operate on]:FILE:_files' \
'--config=[A configuration file to operate on]:FILE:_files' \
'--control=[A control socket, instead of a config]:SOCKET:_files' \
'--config-dir=[A directory of \`*.toml\` configs (default \`/etc/vallum\`)]:DIR:_files' \
'--width=[Snapshot width]:WIDTH:_default' \
'--height=[Snapshot height]:HEIGHT:_default' \
'--snapshot-view=[Snapshot view mode (dashboard, logs, help, qr, empty, filter, ping)]:SNAPSHOT_VIEW:_default' \
'--keys=[A \`tui-keys.toml\` keymap file (default \`\$XDG_CONFIG_HOME/vallum/tui-keys.toml\`)]:FILE:_files' \
'--snapshot[Render one frame headlessly and exit (for CI and the README)]' \
'--ansi[Render snapshot with ANSI colors and styles]' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(uninstall)
_arguments "${_arguments_options[@]}" : \
'--purge[Also remove /etc/vallum — configs and private keys. Without this they stay, so a reinstall brings the same tunnels back up]' \
'--dry-run[Show the full removal plan without changing the host]' \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
&& ret=0
;;
(completions)
_arguments "${_arguments_options[@]}" : \
'--allow-insecure-key-permissions[Use a private key file that its group or the world can read]' \
'-h[Print help (see more with '\''--help'\'')]' \
'--help[Print help (see more with '\''--help'\'')]' \
':shell -- The shell to generate for:(bash elvish fish powershell zsh)' \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
":: :_vallum__subcmd__help_commands" \
"*::: :->help" \
&& ret=0

    case $state in
    (help)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:vallum-help-command-$line[1]:"
        case $line[1] in
            (setup)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(run)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(keygen)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(pubkey)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(genpsk)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(show)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(setconf)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(addconf)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(syncconf)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(showconf)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(bench)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(doctor)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(server)
_arguments "${_arguments_options[@]}" : \
":: :_vallum__subcmd__help__subcmd__server_commands" \
"*::: :->server" \
&& ret=0

    case $state in
    (server)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:vallum-help-server-command-$line[1]:"
        case $line[1] in
            (init)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(enroll)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(teardown)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(client)
_arguments "${_arguments_options[@]}" : \
":: :_vallum__subcmd__help__subcmd__client_commands" \
"*::: :->client" \
&& ret=0

    case $state in
    (client)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:vallum-help-client-command-$line[1]:"
        case $line[1] in
            (teardown)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(join)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(peer)
_arguments "${_arguments_options[@]}" : \
":: :_vallum__subcmd__help__subcmd__peer_commands" \
"*::: :->peer" \
&& ret=0

    case $state in
    (peer)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:vallum-help-peer-command-$line[1]:"
        case $line[1] in
            (add)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(list)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(show)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(remove)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(enroll)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(invite)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(invites)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(rotate)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(finalize)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(metrics)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(identity)
_arguments "${_arguments_options[@]}" : \
":: :_vallum__subcmd__help__subcmd__identity_commands" \
"*::: :->identity" \
&& ret=0

    case $state in
    (identity)
        words=($line[1] "${words[@]}")
        (( CURRENT += 1 ))
        curcontext="${curcontext%:*:*}:vallum-help-identity-command-$line[1]:"
        case $line[1] in
            (issue)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(self-sign)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(verify)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(show)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
(import-bundle)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(enroll-serve)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(tui)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(uninstall)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(completions)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
(help)
_arguments "${_arguments_options[@]}" : \
&& ret=0
;;
        esac
    ;;
esac
;;
        esac
    ;;
esac
}

(( $+functions[_vallum_commands] )) ||
_vallum_commands() {
    local commands; commands=(
'setup:Set this machine up as a server, or as a client' \
'run:Run the tunnel described by a configuration file' \
'keygen:Generate a private key, and print the public line for a peer' \
'pubkey:Print the public line for an existing private key' \
'genpsk:Generate a 32-byte preshared key as 64 hex characters' \
'show:Show a running daemon'\''s device and peers' \
'setconf:Apply a configuration file, replacing every peer' \
'addconf:Add the peers from a configuration file' \
'syncconf:Apply only the differences between a config and the running daemon' \
'showconf:Export a running daemon as a config (secrets are not included)' \
'bench:Measure the data plane'\''s seal/open cost on this host' \
'doctor:Check the platform, config, control socket, and helper tools' \
'server:Prepare this host to be a tunnel server' \
'client:Disconnect and remove a client tunnel installed by \`vallum setup\`' \
'join:Enrol this machine with the one-time ticket \`vallum peer invite\` printed' \
'peer:Enrol, list, inspect, and remove peers' \
'metrics:Print the daemon'\''s state as Prometheus metrics' \
'identity:Issue, sign, verify, and inspect identity documents' \
'import-bundle:Import a client \`.vallum-bundle\` file' \
'enroll-serve:Answer token-gated enrolment requests (runs as its own service)' \
'tui:Operate a tunnel in a terminal dashboard' \
'uninstall:Remove everything the installer and setup put on this host' \
'completions:Print a shell completion script' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'vallum commands' commands "$@"
}
(( $+functions[_vallum__subcmd__addconf_commands] )) ||
_vallum__subcmd__addconf_commands() {
    local commands; commands=()
    _describe -t commands 'vallum addconf commands' commands "$@"
}
(( $+functions[_vallum__subcmd__bench_commands] )) ||
_vallum__subcmd__bench_commands() {
    local commands; commands=()
    _describe -t commands 'vallum bench commands' commands "$@"
}
(( $+functions[_vallum__subcmd__client_commands] )) ||
_vallum__subcmd__client_commands() {
    local commands; commands=(
'teardown:Disconnect and remove a client tunnel installed by \`vallum setup\`' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'vallum client commands' commands "$@"
}
(( $+functions[_vallum__subcmd__client__subcmd__help_commands] )) ||
_vallum__subcmd__client__subcmd__help_commands() {
    local commands; commands=(
'teardown:Disconnect and remove a client tunnel installed by \`vallum setup\`' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'vallum client help commands' commands "$@"
}
(( $+functions[_vallum__subcmd__client__subcmd__help__subcmd__help_commands] )) ||
_vallum__subcmd__client__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'vallum client help help commands' commands "$@"
}
(( $+functions[_vallum__subcmd__client__subcmd__help__subcmd__teardown_commands] )) ||
_vallum__subcmd__client__subcmd__help__subcmd__teardown_commands() {
    local commands; commands=()
    _describe -t commands 'vallum client help teardown commands' commands "$@"
}
(( $+functions[_vallum__subcmd__client__subcmd__teardown_commands] )) ||
_vallum__subcmd__client__subcmd__teardown_commands() {
    local commands; commands=()
    _describe -t commands 'vallum client teardown commands' commands "$@"
}
(( $+functions[_vallum__subcmd__completions_commands] )) ||
_vallum__subcmd__completions_commands() {
    local commands; commands=()
    _describe -t commands 'vallum completions commands' commands "$@"
}
(( $+functions[_vallum__subcmd__doctor_commands] )) ||
_vallum__subcmd__doctor_commands() {
    local commands; commands=()
    _describe -t commands 'vallum doctor commands' commands "$@"
}
(( $+functions[_vallum__subcmd__enroll-serve_commands] )) ||
_vallum__subcmd__enroll-serve_commands() {
    local commands; commands=()
    _describe -t commands 'vallum enroll-serve commands' commands "$@"
}
(( $+functions[_vallum__subcmd__genpsk_commands] )) ||
_vallum__subcmd__genpsk_commands() {
    local commands; commands=()
    _describe -t commands 'vallum genpsk commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help_commands] )) ||
_vallum__subcmd__help_commands() {
    local commands; commands=(
'setup:Set this machine up as a server, or as a client' \
'run:Run the tunnel described by a configuration file' \
'keygen:Generate a private key, and print the public line for a peer' \
'pubkey:Print the public line for an existing private key' \
'genpsk:Generate a 32-byte preshared key as 64 hex characters' \
'show:Show a running daemon'\''s device and peers' \
'setconf:Apply a configuration file, replacing every peer' \
'addconf:Add the peers from a configuration file' \
'syncconf:Apply only the differences between a config and the running daemon' \
'showconf:Export a running daemon as a config (secrets are not included)' \
'bench:Measure the data plane'\''s seal/open cost on this host' \
'doctor:Check the platform, config, control socket, and helper tools' \
'server:Prepare this host to be a tunnel server' \
'client:Disconnect and remove a client tunnel installed by \`vallum setup\`' \
'join:Enrol this machine with the one-time ticket \`vallum peer invite\` printed' \
'peer:Enrol, list, inspect, and remove peers' \
'metrics:Print the daemon'\''s state as Prometheus metrics' \
'identity:Issue, sign, verify, and inspect identity documents' \
'import-bundle:Import a client \`.vallum-bundle\` file' \
'enroll-serve:Answer token-gated enrolment requests (runs as its own service)' \
'tui:Operate a tunnel in a terminal dashboard' \
'uninstall:Remove everything the installer and setup put on this host' \
'completions:Print a shell completion script' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'vallum help commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__addconf_commands] )) ||
_vallum__subcmd__help__subcmd__addconf_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help addconf commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__bench_commands] )) ||
_vallum__subcmd__help__subcmd__bench_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help bench commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__client_commands] )) ||
_vallum__subcmd__help__subcmd__client_commands() {
    local commands; commands=(
'teardown:Disconnect and remove a client tunnel installed by \`vallum setup\`' \
    )
    _describe -t commands 'vallum help client commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__client__subcmd__teardown_commands] )) ||
_vallum__subcmd__help__subcmd__client__subcmd__teardown_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help client teardown commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__completions_commands] )) ||
_vallum__subcmd__help__subcmd__completions_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help completions commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__doctor_commands] )) ||
_vallum__subcmd__help__subcmd__doctor_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help doctor commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__enroll-serve_commands] )) ||
_vallum__subcmd__help__subcmd__enroll-serve_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help enroll-serve commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__genpsk_commands] )) ||
_vallum__subcmd__help__subcmd__genpsk_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help genpsk commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__help_commands] )) ||
_vallum__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help help commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__identity_commands] )) ||
_vallum__subcmd__help__subcmd__identity_commands() {
    local commands; commands=(
'issue:Issue a document signed by a CA key' \
'self-sign:Issue a document signed by the peer'\''s own key' \
'verify:Check a document'\''s signature and window' \
'show:Print a document'\''s label, keys and window without verifying it' \
    )
    _describe -t commands 'vallum help identity commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__identity__subcmd__issue_commands] )) ||
_vallum__subcmd__help__subcmd__identity__subcmd__issue_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help identity issue commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__identity__subcmd__self-sign_commands] )) ||
_vallum__subcmd__help__subcmd__identity__subcmd__self-sign_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help identity self-sign commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__identity__subcmd__show_commands] )) ||
_vallum__subcmd__help__subcmd__identity__subcmd__show_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help identity show commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__identity__subcmd__verify_commands] )) ||
_vallum__subcmd__help__subcmd__identity__subcmd__verify_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help identity verify commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__import-bundle_commands] )) ||
_vallum__subcmd__help__subcmd__import-bundle_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help import-bundle commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__join_commands] )) ||
_vallum__subcmd__help__subcmd__join_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help join commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__keygen_commands] )) ||
_vallum__subcmd__help__subcmd__keygen_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help keygen commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__metrics_commands] )) ||
_vallum__subcmd__help__subcmd__metrics_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help metrics commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__peer_commands] )) ||
_vallum__subcmd__help__subcmd__peer_commands() {
    local commands; commands=(
'add:Enrol a peer and optionally write its client bundle' \
'list:List the configured peers' \
'show:Show one peer' \
'remove:Remove a peer' \
'enroll:Enrol a device that generated its own key, and hand back its config' \
'invite:Mint a single-use token so a device can enrol without SSH access' \
'invites:List live one-time invites and their remaining TTL (pruning expired ones)' \
'rotate:Install a new identity while the old one keeps working' \
'finalize:Retire the previous identity a rotation kept' \
    )
    _describe -t commands 'vallum help peer commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__peer__subcmd__add_commands] )) ||
_vallum__subcmd__help__subcmd__peer__subcmd__add_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help peer add commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__peer__subcmd__enroll_commands] )) ||
_vallum__subcmd__help__subcmd__peer__subcmd__enroll_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help peer enroll commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__peer__subcmd__finalize_commands] )) ||
_vallum__subcmd__help__subcmd__peer__subcmd__finalize_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help peer finalize commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__peer__subcmd__invite_commands] )) ||
_vallum__subcmd__help__subcmd__peer__subcmd__invite_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help peer invite commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__peer__subcmd__invites_commands] )) ||
_vallum__subcmd__help__subcmd__peer__subcmd__invites_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help peer invites commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__peer__subcmd__list_commands] )) ||
_vallum__subcmd__help__subcmd__peer__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help peer list commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__peer__subcmd__remove_commands] )) ||
_vallum__subcmd__help__subcmd__peer__subcmd__remove_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help peer remove commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__peer__subcmd__rotate_commands] )) ||
_vallum__subcmd__help__subcmd__peer__subcmd__rotate_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help peer rotate commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__peer__subcmd__show_commands] )) ||
_vallum__subcmd__help__subcmd__peer__subcmd__show_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help peer show commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__pubkey_commands] )) ||
_vallum__subcmd__help__subcmd__pubkey_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help pubkey commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__run_commands] )) ||
_vallum__subcmd__help__subcmd__run_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help run commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__server_commands] )) ||
_vallum__subcmd__help__subcmd__server_commands() {
    local commands; commands=(
'init:Generate the key, write the config, and start the service' \
'enroll:Turn one-time token enrolment on or off, with its service and port' \
'teardown:Undo the host changes \`server init\` made (units, NAT, firewall, sysctl)' \
    )
    _describe -t commands 'vallum help server commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__server__subcmd__enroll_commands] )) ||
_vallum__subcmd__help__subcmd__server__subcmd__enroll_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help server enroll commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__server__subcmd__init_commands] )) ||
_vallum__subcmd__help__subcmd__server__subcmd__init_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help server init commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__server__subcmd__teardown_commands] )) ||
_vallum__subcmd__help__subcmd__server__subcmd__teardown_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help server teardown commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__setconf_commands] )) ||
_vallum__subcmd__help__subcmd__setconf_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help setconf commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__setup_commands] )) ||
_vallum__subcmd__help__subcmd__setup_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help setup commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__show_commands] )) ||
_vallum__subcmd__help__subcmd__show_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help show commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__showconf_commands] )) ||
_vallum__subcmd__help__subcmd__showconf_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help showconf commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__syncconf_commands] )) ||
_vallum__subcmd__help__subcmd__syncconf_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help syncconf commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__tui_commands] )) ||
_vallum__subcmd__help__subcmd__tui_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help tui commands' commands "$@"
}
(( $+functions[_vallum__subcmd__help__subcmd__uninstall_commands] )) ||
_vallum__subcmd__help__subcmd__uninstall_commands() {
    local commands; commands=()
    _describe -t commands 'vallum help uninstall commands' commands "$@"
}
(( $+functions[_vallum__subcmd__identity_commands] )) ||
_vallum__subcmd__identity_commands() {
    local commands; commands=(
'issue:Issue a document signed by a CA key' \
'self-sign:Issue a document signed by the peer'\''s own key' \
'verify:Check a document'\''s signature and window' \
'show:Print a document'\''s label, keys and window without verifying it' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'vallum identity commands' commands "$@"
}
(( $+functions[_vallum__subcmd__identity__subcmd__help_commands] )) ||
_vallum__subcmd__identity__subcmd__help_commands() {
    local commands; commands=(
'issue:Issue a document signed by a CA key' \
'self-sign:Issue a document signed by the peer'\''s own key' \
'verify:Check a document'\''s signature and window' \
'show:Print a document'\''s label, keys and window without verifying it' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'vallum identity help commands' commands "$@"
}
(( $+functions[_vallum__subcmd__identity__subcmd__help__subcmd__help_commands] )) ||
_vallum__subcmd__identity__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'vallum identity help help commands' commands "$@"
}
(( $+functions[_vallum__subcmd__identity__subcmd__help__subcmd__issue_commands] )) ||
_vallum__subcmd__identity__subcmd__help__subcmd__issue_commands() {
    local commands; commands=()
    _describe -t commands 'vallum identity help issue commands' commands "$@"
}
(( $+functions[_vallum__subcmd__identity__subcmd__help__subcmd__self-sign_commands] )) ||
_vallum__subcmd__identity__subcmd__help__subcmd__self-sign_commands() {
    local commands; commands=()
    _describe -t commands 'vallum identity help self-sign commands' commands "$@"
}
(( $+functions[_vallum__subcmd__identity__subcmd__help__subcmd__show_commands] )) ||
_vallum__subcmd__identity__subcmd__help__subcmd__show_commands() {
    local commands; commands=()
    _describe -t commands 'vallum identity help show commands' commands "$@"
}
(( $+functions[_vallum__subcmd__identity__subcmd__help__subcmd__verify_commands] )) ||
_vallum__subcmd__identity__subcmd__help__subcmd__verify_commands() {
    local commands; commands=()
    _describe -t commands 'vallum identity help verify commands' commands "$@"
}
(( $+functions[_vallum__subcmd__identity__subcmd__issue_commands] )) ||
_vallum__subcmd__identity__subcmd__issue_commands() {
    local commands; commands=()
    _describe -t commands 'vallum identity issue commands' commands "$@"
}
(( $+functions[_vallum__subcmd__identity__subcmd__self-sign_commands] )) ||
_vallum__subcmd__identity__subcmd__self-sign_commands() {
    local commands; commands=()
    _describe -t commands 'vallum identity self-sign commands' commands "$@"
}
(( $+functions[_vallum__subcmd__identity__subcmd__show_commands] )) ||
_vallum__subcmd__identity__subcmd__show_commands() {
    local commands; commands=()
    _describe -t commands 'vallum identity show commands' commands "$@"
}
(( $+functions[_vallum__subcmd__identity__subcmd__verify_commands] )) ||
_vallum__subcmd__identity__subcmd__verify_commands() {
    local commands; commands=()
    _describe -t commands 'vallum identity verify commands' commands "$@"
}
(( $+functions[_vallum__subcmd__import-bundle_commands] )) ||
_vallum__subcmd__import-bundle_commands() {
    local commands; commands=()
    _describe -t commands 'vallum import-bundle commands' commands "$@"
}
(( $+functions[_vallum__subcmd__join_commands] )) ||
_vallum__subcmd__join_commands() {
    local commands; commands=()
    _describe -t commands 'vallum join commands' commands "$@"
}
(( $+functions[_vallum__subcmd__keygen_commands] )) ||
_vallum__subcmd__keygen_commands() {
    local commands; commands=()
    _describe -t commands 'vallum keygen commands' commands "$@"
}
(( $+functions[_vallum__subcmd__metrics_commands] )) ||
_vallum__subcmd__metrics_commands() {
    local commands; commands=()
    _describe -t commands 'vallum metrics commands' commands "$@"
}
(( $+functions[_vallum__subcmd__peer_commands] )) ||
_vallum__subcmd__peer_commands() {
    local commands; commands=(
'add:Enrol a peer and optionally write its client bundle' \
'list:List the configured peers' \
'show:Show one peer' \
'remove:Remove a peer' \
'enroll:Enrol a device that generated its own key, and hand back its config' \
'invite:Mint a single-use token so a device can enrol without SSH access' \
'invites:List live one-time invites and their remaining TTL (pruning expired ones)' \
'rotate:Install a new identity while the old one keeps working' \
'finalize:Retire the previous identity a rotation kept' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'vallum peer commands' commands "$@"
}
(( $+functions[_vallum__subcmd__peer__subcmd__add_commands] )) ||
_vallum__subcmd__peer__subcmd__add_commands() {
    local commands; commands=()
    _describe -t commands 'vallum peer add commands' commands "$@"
}
(( $+functions[_vallum__subcmd__peer__subcmd__enroll_commands] )) ||
_vallum__subcmd__peer__subcmd__enroll_commands() {
    local commands; commands=()
    _describe -t commands 'vallum peer enroll commands' commands "$@"
}
(( $+functions[_vallum__subcmd__peer__subcmd__finalize_commands] )) ||
_vallum__subcmd__peer__subcmd__finalize_commands() {
    local commands; commands=()
    _describe -t commands 'vallum peer finalize commands' commands "$@"
}
(( $+functions[_vallum__subcmd__peer__subcmd__help_commands] )) ||
_vallum__subcmd__peer__subcmd__help_commands() {
    local commands; commands=(
'add:Enrol a peer and optionally write its client bundle' \
'list:List the configured peers' \
'show:Show one peer' \
'remove:Remove a peer' \
'enroll:Enrol a device that generated its own key, and hand back its config' \
'invite:Mint a single-use token so a device can enrol without SSH access' \
'invites:List live one-time invites and their remaining TTL (pruning expired ones)' \
'rotate:Install a new identity while the old one keeps working' \
'finalize:Retire the previous identity a rotation kept' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'vallum peer help commands' commands "$@"
}
(( $+functions[_vallum__subcmd__peer__subcmd__help__subcmd__add_commands] )) ||
_vallum__subcmd__peer__subcmd__help__subcmd__add_commands() {
    local commands; commands=()
    _describe -t commands 'vallum peer help add commands' commands "$@"
}
(( $+functions[_vallum__subcmd__peer__subcmd__help__subcmd__enroll_commands] )) ||
_vallum__subcmd__peer__subcmd__help__subcmd__enroll_commands() {
    local commands; commands=()
    _describe -t commands 'vallum peer help enroll commands' commands "$@"
}
(( $+functions[_vallum__subcmd__peer__subcmd__help__subcmd__finalize_commands] )) ||
_vallum__subcmd__peer__subcmd__help__subcmd__finalize_commands() {
    local commands; commands=()
    _describe -t commands 'vallum peer help finalize commands' commands "$@"
}
(( $+functions[_vallum__subcmd__peer__subcmd__help__subcmd__help_commands] )) ||
_vallum__subcmd__peer__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'vallum peer help help commands' commands "$@"
}
(( $+functions[_vallum__subcmd__peer__subcmd__help__subcmd__invite_commands] )) ||
_vallum__subcmd__peer__subcmd__help__subcmd__invite_commands() {
    local commands; commands=()
    _describe -t commands 'vallum peer help invite commands' commands "$@"
}
(( $+functions[_vallum__subcmd__peer__subcmd__help__subcmd__invites_commands] )) ||
_vallum__subcmd__peer__subcmd__help__subcmd__invites_commands() {
    local commands; commands=()
    _describe -t commands 'vallum peer help invites commands' commands "$@"
}
(( $+functions[_vallum__subcmd__peer__subcmd__help__subcmd__list_commands] )) ||
_vallum__subcmd__peer__subcmd__help__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'vallum peer help list commands' commands "$@"
}
(( $+functions[_vallum__subcmd__peer__subcmd__help__subcmd__remove_commands] )) ||
_vallum__subcmd__peer__subcmd__help__subcmd__remove_commands() {
    local commands; commands=()
    _describe -t commands 'vallum peer help remove commands' commands "$@"
}
(( $+functions[_vallum__subcmd__peer__subcmd__help__subcmd__rotate_commands] )) ||
_vallum__subcmd__peer__subcmd__help__subcmd__rotate_commands() {
    local commands; commands=()
    _describe -t commands 'vallum peer help rotate commands' commands "$@"
}
(( $+functions[_vallum__subcmd__peer__subcmd__help__subcmd__show_commands] )) ||
_vallum__subcmd__peer__subcmd__help__subcmd__show_commands() {
    local commands; commands=()
    _describe -t commands 'vallum peer help show commands' commands "$@"
}
(( $+functions[_vallum__subcmd__peer__subcmd__invite_commands] )) ||
_vallum__subcmd__peer__subcmd__invite_commands() {
    local commands; commands=()
    _describe -t commands 'vallum peer invite commands' commands "$@"
}
(( $+functions[_vallum__subcmd__peer__subcmd__invites_commands] )) ||
_vallum__subcmd__peer__subcmd__invites_commands() {
    local commands; commands=()
    _describe -t commands 'vallum peer invites commands' commands "$@"
}
(( $+functions[_vallum__subcmd__peer__subcmd__list_commands] )) ||
_vallum__subcmd__peer__subcmd__list_commands() {
    local commands; commands=()
    _describe -t commands 'vallum peer list commands' commands "$@"
}
(( $+functions[_vallum__subcmd__peer__subcmd__remove_commands] )) ||
_vallum__subcmd__peer__subcmd__remove_commands() {
    local commands; commands=()
    _describe -t commands 'vallum peer remove commands' commands "$@"
}
(( $+functions[_vallum__subcmd__peer__subcmd__rotate_commands] )) ||
_vallum__subcmd__peer__subcmd__rotate_commands() {
    local commands; commands=()
    _describe -t commands 'vallum peer rotate commands' commands "$@"
}
(( $+functions[_vallum__subcmd__peer__subcmd__show_commands] )) ||
_vallum__subcmd__peer__subcmd__show_commands() {
    local commands; commands=()
    _describe -t commands 'vallum peer show commands' commands "$@"
}
(( $+functions[_vallum__subcmd__pubkey_commands] )) ||
_vallum__subcmd__pubkey_commands() {
    local commands; commands=()
    _describe -t commands 'vallum pubkey commands' commands "$@"
}
(( $+functions[_vallum__subcmd__run_commands] )) ||
_vallum__subcmd__run_commands() {
    local commands; commands=()
    _describe -t commands 'vallum run commands' commands "$@"
}
(( $+functions[_vallum__subcmd__server_commands] )) ||
_vallum__subcmd__server_commands() {
    local commands; commands=(
'init:Generate the key, write the config, and start the service' \
'enroll:Turn one-time token enrolment on or off, with its service and port' \
'teardown:Undo the host changes \`server init\` made (units, NAT, firewall, sysctl)' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'vallum server commands' commands "$@"
}
(( $+functions[_vallum__subcmd__server__subcmd__enroll_commands] )) ||
_vallum__subcmd__server__subcmd__enroll_commands() {
    local commands; commands=()
    _describe -t commands 'vallum server enroll commands' commands "$@"
}
(( $+functions[_vallum__subcmd__server__subcmd__help_commands] )) ||
_vallum__subcmd__server__subcmd__help_commands() {
    local commands; commands=(
'init:Generate the key, write the config, and start the service' \
'enroll:Turn one-time token enrolment on or off, with its service and port' \
'teardown:Undo the host changes \`server init\` made (units, NAT, firewall, sysctl)' \
'help:Print this message or the help of the given subcommand(s)' \
    )
    _describe -t commands 'vallum server help commands' commands "$@"
}
(( $+functions[_vallum__subcmd__server__subcmd__help__subcmd__enroll_commands] )) ||
_vallum__subcmd__server__subcmd__help__subcmd__enroll_commands() {
    local commands; commands=()
    _describe -t commands 'vallum server help enroll commands' commands "$@"
}
(( $+functions[_vallum__subcmd__server__subcmd__help__subcmd__help_commands] )) ||
_vallum__subcmd__server__subcmd__help__subcmd__help_commands() {
    local commands; commands=()
    _describe -t commands 'vallum server help help commands' commands "$@"
}
(( $+functions[_vallum__subcmd__server__subcmd__help__subcmd__init_commands] )) ||
_vallum__subcmd__server__subcmd__help__subcmd__init_commands() {
    local commands; commands=()
    _describe -t commands 'vallum server help init commands' commands "$@"
}
(( $+functions[_vallum__subcmd__server__subcmd__help__subcmd__teardown_commands] )) ||
_vallum__subcmd__server__subcmd__help__subcmd__teardown_commands() {
    local commands; commands=()
    _describe -t commands 'vallum server help teardown commands' commands "$@"
}
(( $+functions[_vallum__subcmd__server__subcmd__init_commands] )) ||
_vallum__subcmd__server__subcmd__init_commands() {
    local commands; commands=()
    _describe -t commands 'vallum server init commands' commands "$@"
}
(( $+functions[_vallum__subcmd__server__subcmd__teardown_commands] )) ||
_vallum__subcmd__server__subcmd__teardown_commands() {
    local commands; commands=()
    _describe -t commands 'vallum server teardown commands' commands "$@"
}
(( $+functions[_vallum__subcmd__setconf_commands] )) ||
_vallum__subcmd__setconf_commands() {
    local commands; commands=()
    _describe -t commands 'vallum setconf commands' commands "$@"
}
(( $+functions[_vallum__subcmd__setup_commands] )) ||
_vallum__subcmd__setup_commands() {
    local commands; commands=()
    _describe -t commands 'vallum setup commands' commands "$@"
}
(( $+functions[_vallum__subcmd__show_commands] )) ||
_vallum__subcmd__show_commands() {
    local commands; commands=()
    _describe -t commands 'vallum show commands' commands "$@"
}
(( $+functions[_vallum__subcmd__showconf_commands] )) ||
_vallum__subcmd__showconf_commands() {
    local commands; commands=()
    _describe -t commands 'vallum showconf commands' commands "$@"
}
(( $+functions[_vallum__subcmd__syncconf_commands] )) ||
_vallum__subcmd__syncconf_commands() {
    local commands; commands=()
    _describe -t commands 'vallum syncconf commands' commands "$@"
}
(( $+functions[_vallum__subcmd__tui_commands] )) ||
_vallum__subcmd__tui_commands() {
    local commands; commands=()
    _describe -t commands 'vallum tui commands' commands "$@"
}
(( $+functions[_vallum__subcmd__uninstall_commands] )) ||
_vallum__subcmd__uninstall_commands() {
    local commands; commands=()
    _describe -t commands 'vallum uninstall commands' commands "$@"
}

if [ "$funcstack[1]" = "_vallum" ]; then
    _vallum "$@"
else
    compdef _vallum vallum
fi
