# Print an optspec for argparse to handle cmd's options that are independent of any subcommand.
function __fish_vallum_global_optspecs
    string join \n allow-insecure-key-permissions h/help V/version
end

function __fish_vallum_needs_command
    # Figure out if the current invocation already has a command.
    set -l cmd (commandline -opc)
    set -e cmd[1]
    argparse -s (__fish_vallum_global_optspecs) -- $cmd 2>/dev/null
    or return
    if set -q argv[1]
        # Also print the command, so this can be used to figure out what it is.
        echo $argv[1]
        return 1
    end
    return 0
end

function __fish_vallum_using_subcommand
    set -l cmd (__fish_vallum_needs_command)
    test -z "$cmd"
    and return 1
    contains -- $cmd[1] $argv
end

complete -c vallum -n "__fish_vallum_needs_command" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_needs_command" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_needs_command" -s V -l version -d 'Print version'
complete -c vallum -n "__fish_vallum_needs_command" -f -a "setup" -d 'Set this machine up as a server, or as a client'
complete -c vallum -n "__fish_vallum_needs_command" -f -a "run" -d 'Run the tunnel described by a configuration file'
complete -c vallum -n "__fish_vallum_needs_command" -f -a "keygen" -d 'Generate a private key, and print the public line for a peer'
complete -c vallum -n "__fish_vallum_needs_command" -f -a "pubkey" -d 'Print the public line for an existing private key'
complete -c vallum -n "__fish_vallum_needs_command" -f -a "genpsk" -d 'Generate a 32-byte preshared key as 64 hex characters'
complete -c vallum -n "__fish_vallum_needs_command" -f -a "show" -d 'Show a running daemon\'s device and peers'
complete -c vallum -n "__fish_vallum_needs_command" -f -a "setconf" -d 'Apply a configuration file, replacing every peer'
complete -c vallum -n "__fish_vallum_needs_command" -f -a "addconf" -d 'Add the peers from a configuration file'
complete -c vallum -n "__fish_vallum_needs_command" -f -a "syncconf" -d 'Apply only the differences between a config and the running daemon'
complete -c vallum -n "__fish_vallum_needs_command" -f -a "showconf" -d 'Export a running daemon as a config (secrets are not included)'
complete -c vallum -n "__fish_vallum_needs_command" -f -a "bench" -d 'Measure the data plane\'s seal/open cost on this host'
complete -c vallum -n "__fish_vallum_needs_command" -f -a "doctor" -d 'Check the platform, config, control socket, and helper tools'
complete -c vallum -n "__fish_vallum_needs_command" -f -a "server" -d 'Prepare this host to be a tunnel server'
complete -c vallum -n "__fish_vallum_needs_command" -f -a "client" -d 'Disconnect and remove a client tunnel installed by `vallum setup`'
complete -c vallum -n "__fish_vallum_needs_command" -f -a "join" -d 'Enrol this machine with the one-time ticket `vallum peer invite` printed'
complete -c vallum -n "__fish_vallum_needs_command" -f -a "peer" -d 'Enrol, list, inspect, and remove peers'
complete -c vallum -n "__fish_vallum_needs_command" -f -a "metrics" -d 'Print the daemon\'s state as Prometheus metrics'
complete -c vallum -n "__fish_vallum_needs_command" -f -a "identity" -d 'Issue, sign, verify, and inspect identity documents'
complete -c vallum -n "__fish_vallum_needs_command" -f -a "import-bundle" -d 'Import a client `.vallum-bundle` file'
complete -c vallum -n "__fish_vallum_needs_command" -f -a "enroll-serve" -d 'Answer token-gated enrolment requests (runs as its own service)'
complete -c vallum -n "__fish_vallum_needs_command" -f -a "tui" -d 'Operate a tunnel in a terminal dashboard'
complete -c vallum -n "__fish_vallum_needs_command" -f -a "completions" -d 'Print a shell completion script'
complete -c vallum -n "__fish_vallum_needs_command" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c vallum -n "__fish_vallum_using_subcommand setup" -l client -d 'This machine connects to a server, from a `.vallum-bundle` file' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand setup" -l endpoint -d 'The address clients dial. Detected when absent' -r
complete -c vallum -n "__fish_vallum_using_subcommand setup" -l address -d 'The tunnel address and prefix' -r
complete -c vallum -n "__fish_vallum_using_subcommand setup" -l listen -d 'The UDP address to listen on' -r
complete -c vallum -n "__fish_vallum_using_subcommand setup" -l name -d 'The instance name: the config file stem and the unit instance' -r
complete -c vallum -n "__fish_vallum_using_subcommand setup" -l remote -d 'Enrol this machine against a server over SSH, which needs no bundle and never sends this machine\'s private key anywhere' -r
complete -c vallum -n "__fish_vallum_using_subcommand setup" -l remote-config -d 'The server config to edit when enrolling with `--remote` (for a server whose instance is not `vallum0`)' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand setup" -l join -d 'Enrol with a single-use token, for machines that cannot SSH to the server. Takes the `vallum1-join:…` ticket `vallum peer invite` prints, or a bare `host:port` together with --invite-id and --token' -r
complete -c vallum -n "__fish_vallum_using_subcommand setup" -l token -d 'The single-use token from `vallum peer invite`, or `-` to read it from stdin so it stays out of shell history and `ps`' -r
complete -c vallum -n "__fish_vallum_using_subcommand setup" -l invite-id -d 'The invite id from `vallum peer invite` (32 hex characters)' -r
complete -c vallum -n "__fish_vallum_using_subcommand setup" -l expect -d 'Refuse the answer unless the server\'s fingerprint matches this. Printed by `vallum peer invite`; it is how a client knows it reached the right server rather than one that answered first' -r
complete -c vallum -n "__fish_vallum_using_subcommand setup" -l server -d 'This machine accepts clients'
complete -c vallum -n "__fish_vallum_using_subcommand setup" -l yes -d 'Take the defaults and the host changes without asking'
complete -c vallum -n "__fish_vallum_using_subcommand setup" -l enroll -d 'On a server, allow devices to enrol with a one-time token (opens UDP `listen + 1`)'
complete -c vallum -n "__fish_vallum_using_subcommand setup" -l dry-run -d 'Print every step and change nothing'
complete -c vallum -n "__fish_vallum_using_subcommand setup" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand setup" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand run" -s c -l config -d 'The configuration file' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand run" -l tick-ms -d 'How often the loop wakes with nothing to do, in milliseconds' -r
complete -c vallum -n "__fish_vallum_using_subcommand run" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand run" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand keygen" -s o -l output -d 'Where to write the private key. Refuses to overwrite an existing file' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand keygen" -l suite -d 'The suite id, decimal or `0x`-prefixed hex. Defaults to the tri-hybrid' -r
complete -c vallum -n "__fish_vallum_using_subcommand keygen" -l signing -d 'Also derive a hybrid signing key pair, turning on P3 identity'
complete -c vallum -n "__fish_vallum_using_subcommand keygen" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand keygen" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand pubkey" -s k -l private-key -d 'The private key to read' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand pubkey" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand pubkey" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand genpsk" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand genpsk" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand show" -s c -l config -d 'The configuration file, for its `control` path' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand show" -l control -d 'The control socket path, instead of a config' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand show" -l interval -d 'Refresh interval for `--watch`, in milliseconds' -r
complete -c vallum -n "__fish_vallum_using_subcommand show" -l field -d 'Print only one field (endpoints, allowed-ips, transfer, ...)' -r
complete -c vallum -n "__fish_vallum_using_subcommand show" -l dump -d 'Print the raw UAPI response'
complete -c vallum -n "__fish_vallum_using_subcommand show" -l json -d 'Emit the secret-free JSON view'
complete -c vallum -n "__fish_vallum_using_subcommand show" -l watch -d 'Refresh the view until Ctrl-C'
complete -c vallum -n "__fish_vallum_using_subcommand show" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand show" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand setconf" -l control -d 'The control socket path, instead of the config\'s `control` field' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand setconf" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand setconf" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand addconf" -l control -d 'The control socket path, instead of the config\'s `control` field' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand addconf" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand addconf" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand syncconf" -l control -d 'The control socket path, instead of the config\'s `control` field' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand syncconf" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand syncconf" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand showconf" -s c -l config -d 'The configuration file, for its `control` path' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand showconf" -l control -d 'The control socket path, instead of a config' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand showconf" -l include-secrets -d 'Include the private-key path and preshared keys in the export'
complete -c vallum -n "__fish_vallum_using_subcommand showconf" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand showconf" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand bench" -l suite -d 'The suite id, decimal or `0x`-prefixed hex. Defaults to the tri-hybrid' -r
complete -c vallum -n "__fish_vallum_using_subcommand bench" -l bytes -d 'Payload size in bytes' -r
complete -c vallum -n "__fish_vallum_using_subcommand bench" -l iterations -d 'Iterations to time' -r
complete -c vallum -n "__fish_vallum_using_subcommand bench" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand bench" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand doctor" -s c -l config -d 'The configuration file to check' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand doctor" -l control -d 'The control socket to query, instead of the config\'s `control`' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand doctor" -l probe-mtu -d 'Probe the path MTU to this host with `ping -M do` and compare it with the config\'s `outer_mtu`' -r
complete -c vallum -n "__fish_vallum_using_subcommand doctor" -l json -d 'Emit JSON instead of a table'
complete -c vallum -n "__fish_vallum_using_subcommand doctor" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand doctor" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand server; and not __fish_seen_subcommand_from init enroll teardown help" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand server; and not __fish_seen_subcommand_from init enroll teardown help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand server; and not __fish_seen_subcommand_from init enroll teardown help" -f -a "init" -d 'Generate the key, write the config, and start the service'
complete -c vallum -n "__fish_vallum_using_subcommand server; and not __fish_seen_subcommand_from init enroll teardown help" -f -a "enroll" -d 'Turn one-time token enrolment on or off, with its service and port'
complete -c vallum -n "__fish_vallum_using_subcommand server; and not __fish_seen_subcommand_from init enroll teardown help" -f -a "teardown" -d 'Undo the host changes `server init` made (units, NAT, firewall, sysctl)'
complete -c vallum -n "__fish_vallum_using_subcommand server; and not __fish_seen_subcommand_from init enroll teardown help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from init" -l config -d 'The configuration file to write' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from init" -l name -d 'The kernel interface name. Defaults to the config file\'s stem' -r
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from init" -l address -d 'The address and prefix for the interface. Repeat for dual-stack' -r
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from init" -l listen -d 'The UDP address to listen on' -r
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from init" -l endpoint -d 'The address clients dial, printed in their bundles. Detected if absent' -r
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from init" -l control -d 'The control socket path. Defaults to /run/vallum/<name>.sock' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from init" -l dns -d 'A DNS server to push to clients through `[quick]`. Repeatable' -r
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from init" -l user -d 'The user to drop to after the interface and socket are open' -r
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from init" -l enroll -d 'Allow devices to enrol with a one-time token, which opens UDP `listen + 1` and enables the `vallum-enroll@` unit'
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from init" -l no-nat -d 'Do not install the masquerade rule'
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from init" -l no-firewall -d 'Do not open the UDP port in the host firewall'
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from init" -l no-forward -d 'Do not enable IP forwarding'
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from init" -l no-service -d 'Do not install or start the systemd units'
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from init" -l no-host -d 'Do not change anything about the host (implies the three `--no-*` above)'
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from init" -l dry-run -d 'Print every step and change nothing'
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from init" -l force -d 'Rewrite an existing config (the key is never regenerated)'
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from init" -l json -d 'Emit JSON instead of a report'
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from init" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from init" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from enroll" -l config -d 'The configuration file to change' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from enroll" -l enable -d 'Allow devices to enrol with a one-time token'
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from enroll" -l disable -d 'Stop answering enrolment requests, and try to close the port'
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from enroll" -l dry-run -d 'Show what would change, without changing it'
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from enroll" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from enroll" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from teardown" -l config -d 'The server configuration file to tear down' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from teardown" -l purge -d 'Also delete the config file and keys in `/etc/vallum`. Without this, they stay in place so `server init` can bring the same server back up'
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from teardown" -l dry-run -d 'Show what would be removed, without changing the host'
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from teardown" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from teardown" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from help" -f -a "init" -d 'Generate the key, write the config, and start the service'
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from help" -f -a "enroll" -d 'Turn one-time token enrolment on or off, with its service and port'
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from help" -f -a "teardown" -d 'Undo the host changes `server init` made (units, NAT, firewall, sysctl)'
complete -c vallum -n "__fish_vallum_using_subcommand server; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c vallum -n "__fish_vallum_using_subcommand client; and not __fish_seen_subcommand_from teardown help" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand client; and not __fish_seen_subcommand_from teardown help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand client; and not __fish_seen_subcommand_from teardown help" -f -a "teardown" -d 'Disconnect and remove a client tunnel installed by `vallum setup`'
complete -c vallum -n "__fish_vallum_using_subcommand client; and not __fish_seen_subcommand_from teardown help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c vallum -n "__fish_vallum_using_subcommand client; and __fish_seen_subcommand_from teardown" -l config -d 'The client configuration file to tear down' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand client; and __fish_seen_subcommand_from teardown" -l name -d 'The client name — resolves to `/etc/vallum/<name>.toml`' -r
complete -c vallum -n "__fish_vallum_using_subcommand client; and __fish_seen_subcommand_from teardown" -l purge -d 'Also delete the config file and key in `/etc/vallum`. Without this, they stay in place so the tunnel can be brought back up'
complete -c vallum -n "__fish_vallum_using_subcommand client; and __fish_seen_subcommand_from teardown" -l dry-run -d 'Show what would be removed, without changing the host'
complete -c vallum -n "__fish_vallum_using_subcommand client; and __fish_seen_subcommand_from teardown" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand client; and __fish_seen_subcommand_from teardown" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand client; and __fish_seen_subcommand_from help" -f -a "teardown" -d 'Disconnect and remove a client tunnel installed by `vallum setup`'
complete -c vallum -n "__fish_vallum_using_subcommand client; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c vallum -n "__fish_vallum_using_subcommand join" -l name -d 'The name this machine\'s config files take. Defaults to the name the invite was minted for' -r
complete -c vallum -n "__fish_vallum_using_subcommand join" -l dry-run -d 'Print every step and change nothing'
complete -c vallum -n "__fish_vallum_using_subcommand join" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand join" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and not __fish_seen_subcommand_from add list show remove enroll invite invites rotate finalize help" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and not __fish_seen_subcommand_from add list show remove enroll invite invites rotate finalize help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and not __fish_seen_subcommand_from add list show remove enroll invite invites rotate finalize help" -f -a "add" -d 'Enrol a peer and optionally write its client bundle'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and not __fish_seen_subcommand_from add list show remove enroll invite invites rotate finalize help" -f -a "list" -d 'List the configured peers'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and not __fish_seen_subcommand_from add list show remove enroll invite invites rotate finalize help" -f -a "show" -d 'Show one peer'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and not __fish_seen_subcommand_from add list show remove enroll invite invites rotate finalize help" -f -a "remove" -d 'Remove a peer'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and not __fish_seen_subcommand_from add list show remove enroll invite invites rotate finalize help" -f -a "enroll" -d 'Enrol a device that generated its own key, and hand back its config'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and not __fish_seen_subcommand_from add list show remove enroll invite invites rotate finalize help" -f -a "invite" -d 'Mint a single-use token so a device can enrol without SSH access'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and not __fish_seen_subcommand_from add list show remove enroll invite invites rotate finalize help" -f -a "invites" -d 'List live one-time invites and their remaining TTL (pruning expired ones)'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and not __fish_seen_subcommand_from add list show remove enroll invite invites rotate finalize help" -f -a "rotate" -d 'Install a new identity while the old one keeps working'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and not __fish_seen_subcommand_from add list show remove enroll invite invites rotate finalize help" -f -a "finalize" -d 'Retire the previous identity a rotation kept'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and not __fish_seen_subcommand_from add list show remove enroll invite invites rotate finalize help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from add" -l config -d 'The configuration file to edit' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from add" -l public-key -d 'The peer\'s public line (the device generated its own key)' -r
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from add" -l public-key-file -d 'A file holding the peer\'s public line' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from add" -l bundle-out -d 'Generate the keypair here and write the client\'s bundle to this path' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from add" -l client-config-out -d 'Write the client\'s config to this path (no private key: the device has its own). Use with `--public-key`' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from add" -l identity -d 'Enrol a peer by its identity document instead of a public line' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from add" -l address -d 'The address to route to the peer. Allocated if absent' -r
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from add" -l allowed-ips -d 'The prefixes routed to the peer. Defaults to the peer\'s address' -r
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from add" -l endpoint -d 'The address the client dials. Detected for a bundle if absent' -r
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from add" -l keepalive -d 'Send a keepalive every this many seconds' -r
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from add" -l dns -d 'A DNS server to push to the client bundle. Repeatable' -r
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from add" -l ship-key -d 'Confirm that this server should generate the device\'s key and hand it over. Only for devices that cannot generate their own'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from add" -l pin-endpoint -d 'Refuse handshakes from any address other than `--endpoint`'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from add" -l psk -d 'Generate a preshared key and store it next to the config'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from add" -l forget-key -d 'Delete the server\'s copy of the client key after writing the bundle'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from add" -l no-apply -d 'Write the config but do not tell a running daemon'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from add" -l json -d 'Emit JSON instead of a report'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from add" -l full -d 'Include the full public line in JSON output'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from add" -l quiet -d 'Suppress the report. Used by `peer enroll`, which prints its own'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from add" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from add" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from list" -l config -d 'The configuration file to read' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from list" -l full -d 'Include the full public line, not just its fingerprint'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from list" -l json -d 'Emit JSON instead of a table'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from list" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from list" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from show" -l config -d 'The configuration file to read' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from show" -l full -d 'Print the full public line'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from show" -l json -d 'Emit JSON instead of a report'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from show" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from show" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from remove" -l config -d 'The configuration file to edit' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from remove" -l no-apply -d 'Write the config but do not tell a running daemon'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from remove" -l json -d 'Emit JSON instead of a report'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from remove" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from remove" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from enroll" -l config -d 'The configuration file to edit' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from enroll" -l public-key -d 'The device\'s public line, generated on the device itself' -r
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from enroll" -l public-key-file -d 'A file holding the device\'s public line' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from enroll" -l address -d 'The address to route to the device. Allocated if absent' -r
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from enroll" -l keepalive -d 'Send a keepalive every this many seconds' -r
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from enroll" -l no-apply -d 'Write the config but do not tell a running daemon'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from enroll" -l json -d 'Emit JSON instead of a report'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from enroll" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from enroll" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from invite" -l config -d 'The configuration file this invite is for' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from invite" -l public-key -d 'Bind the invite to the device\'s public line: a stolen token then enrols nothing, because the attacker has no matching private key' -r
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from invite" -l public-key-file -d 'A file holding the device\'s public line' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from invite" -l ttl -d 'How long the invite lives, in minutes' -r
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from invite" -l json -d 'Emit JSON instead of a report'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from invite" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from invite" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from invites" -l config -d 'The configuration file whose interface to inspect' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from invites" -l json -d 'Emit JSON instead of a table (tokens are never printed here)'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from invites" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from invites" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from rotate" -l config -d 'The configuration file to edit' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from rotate" -l public-key -d 'The peer\'s new public line' -r
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from rotate" -l public-key-file -d 'A file holding the new public line' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from rotate" -l bundle-out -d 'Generate the new keypair here and write the client\'s bundle' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from rotate" -l identity -d 'The peer\'s new identity document' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from rotate" -l endpoint -d 'The address the client dials, for the bundle. Detected if absent' -r
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from rotate" -l dns -d 'A DNS server to push to the client bundle. Repeatable' -r
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from rotate" -l ship-key -d 'Confirm that this server should generate the replacement key'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from rotate" -l forget-key -d 'Delete the server\'s copy of the generated key after writing the bundle'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from rotate" -l no-apply -d 'Write the config but do not tell a running daemon'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from rotate" -l json -d 'Emit JSON instead of a report'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from rotate" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from rotate" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from finalize" -l config -d 'The configuration file to edit' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from finalize" -l no-apply -d 'Write the config but do not tell a running daemon'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from finalize" -l json -d 'Emit JSON instead of a report'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from finalize" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from finalize" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from help" -f -a "add" -d 'Enrol a peer and optionally write its client bundle'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from help" -f -a "list" -d 'List the configured peers'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from help" -f -a "show" -d 'Show one peer'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from help" -f -a "remove" -d 'Remove a peer'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from help" -f -a "enroll" -d 'Enrol a device that generated its own key, and hand back its config'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from help" -f -a "invite" -d 'Mint a single-use token so a device can enrol without SSH access'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from help" -f -a "invites" -d 'List live one-time invites and their remaining TTL (pruning expired ones)'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from help" -f -a "rotate" -d 'Install a new identity while the old one keeps working'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from help" -f -a "finalize" -d 'Retire the previous identity a rotation kept'
complete -c vallum -n "__fish_vallum_using_subcommand peer; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c vallum -n "__fish_vallum_using_subcommand metrics" -s c -l config -d 'The configuration file, for its `control` path' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand metrics" -l control -d 'The control socket path, instead of a config' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand metrics" -l prefix -d 'The metric name prefix' -r
complete -c vallum -n "__fish_vallum_using_subcommand metrics" -l output -d 'Write the exposition to a file instead of stdout' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand metrics" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand metrics" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand identity; and not __fish_seen_subcommand_from issue self-sign verify show help" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand identity; and not __fish_seen_subcommand_from issue self-sign verify show help" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand identity; and not __fish_seen_subcommand_from issue self-sign verify show help" -f -a "issue" -d 'Issue a document signed by a CA key'
complete -c vallum -n "__fish_vallum_using_subcommand identity; and not __fish_seen_subcommand_from issue self-sign verify show help" -f -a "self-sign" -d 'Issue a document signed by the peer\'s own key'
complete -c vallum -n "__fish_vallum_using_subcommand identity; and not __fish_seen_subcommand_from issue self-sign verify show help" -f -a "verify" -d 'Check a document\'s signature and window'
complete -c vallum -n "__fish_vallum_using_subcommand identity; and not __fish_seen_subcommand_from issue self-sign verify show help" -f -a "show" -d 'Print a document\'s label, keys and window without verifying it'
complete -c vallum -n "__fish_vallum_using_subcommand identity; and not __fish_seen_subcommand_from issue self-sign verify show help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from issue" -l ca-key -d 'The CA key, which must carry a signing half (`keygen --signing`)' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from issue" -l peer-public -d 'The peer\'s public line, which must carry a signing key' -r
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from issue" -l peer-public-file -d 'A file holding the peer\'s public line' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from issue" -l label -d 'A name for the document, for logs and `peer show`' -r
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from issue" -l days -d 'How long the document is valid, in days' -r
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from issue" -l not-before -d 'The first second the document is valid. Defaults to now' -r
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from issue" -l output -d 'Write the document here (0600) instead of stdout' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from issue" -l json -d 'Emit JSON instead of the document text'
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from issue" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from issue" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from self-sign" -l key -d 'The peer\'s own key, which must carry a signing half' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from self-sign" -l label -d 'A name for the document' -r
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from self-sign" -l days -d 'How long the document is valid, in days' -r
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from self-sign" -l not-before -d 'The first second the document is valid. Defaults to now' -r
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from self-sign" -l output -d 'Write the document here (0600) instead of stdout' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from self-sign" -l json -d 'Emit JSON instead of the document text'
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from self-sign" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from self-sign" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from verify" -l issuer -d 'A file holding the issuer\'s `vallum1:` public line — what `vallum keygen` prints. Verification never needs the CA\'s private key' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from verify" -l issuer-public -d 'The issuer\'s public line, instead of a file' -r
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from verify" -l document -d 'The document to check' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from verify" -l suite -d 'The suite to verify a self-signed document with' -r
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from verify" -l json -d 'Emit JSON instead of a report'
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from verify" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from verify" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from show" -l document -d 'The document to inspect' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from show" -l suite -d 'The suite the document was encoded under' -r
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from show" -l json -d 'Emit JSON instead of a report'
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from show" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from show" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from help" -f -a "issue" -d 'Issue a document signed by a CA key'
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from help" -f -a "self-sign" -d 'Issue a document signed by the peer\'s own key'
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from help" -f -a "verify" -d 'Check a document\'s signature and window'
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from help" -f -a "show" -d 'Print a document\'s label, keys and window without verifying it'
complete -c vallum -n "__fish_vallum_using_subcommand identity; and __fish_seen_subcommand_from help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c vallum -n "__fish_vallum_using_subcommand import-bundle" -l output-dir -d 'Directory for the config and key (default: /etc/vallum with --install, the current directory otherwise)' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand import-bundle" -l force -d 'Overwrite an existing config or key'
complete -c vallum -n "__fish_vallum_using_subcommand import-bundle" -l install -d 'Install to /etc/vallum, install the units, and start the tunnel'
complete -c vallum -n "__fish_vallum_using_subcommand import-bundle" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand import-bundle" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand enroll-serve" -l config -d 'The configuration file whose `[enroll]` section governs the responder' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand enroll-serve" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand enroll-serve" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand tui" -s c -l config -d 'A configuration file to operate on' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand tui" -l control -d 'A control socket, instead of a config' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand tui" -l config-dir -d 'A directory of `*.toml` configs (default `/etc/vallum`)' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand tui" -l width -d 'Snapshot width' -r
complete -c vallum -n "__fish_vallum_using_subcommand tui" -l height -d 'Snapshot height' -r
complete -c vallum -n "__fish_vallum_using_subcommand tui" -l snapshot-view -d 'Snapshot view mode (dashboard, logs, help, qr, empty, filter, ping)' -r
complete -c vallum -n "__fish_vallum_using_subcommand tui" -l keys -d 'A `tui-keys.toml` keymap file (default `$XDG_CONFIG_HOME/vallum/tui-keys.toml`)' -r -F
complete -c vallum -n "__fish_vallum_using_subcommand tui" -l snapshot -d 'Render one frame headlessly and exit (for CI and the README)'
complete -c vallum -n "__fish_vallum_using_subcommand tui" -l ansi -d 'Render snapshot with ANSI colors and styles'
complete -c vallum -n "__fish_vallum_using_subcommand tui" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand tui" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand completions" -l allow-insecure-key-permissions -d 'Use a private key file that its group or the world can read'
complete -c vallum -n "__fish_vallum_using_subcommand completions" -s h -l help -d 'Print help (see more with \'--help\')'
complete -c vallum -n "__fish_vallum_using_subcommand help; and not __fish_seen_subcommand_from setup run keygen pubkey genpsk show setconf addconf syncconf showconf bench doctor server client join peer metrics identity import-bundle enroll-serve tui completions help" -f -a "setup" -d 'Set this machine up as a server, or as a client'
complete -c vallum -n "__fish_vallum_using_subcommand help; and not __fish_seen_subcommand_from setup run keygen pubkey genpsk show setconf addconf syncconf showconf bench doctor server client join peer metrics identity import-bundle enroll-serve tui completions help" -f -a "run" -d 'Run the tunnel described by a configuration file'
complete -c vallum -n "__fish_vallum_using_subcommand help; and not __fish_seen_subcommand_from setup run keygen pubkey genpsk show setconf addconf syncconf showconf bench doctor server client join peer metrics identity import-bundle enroll-serve tui completions help" -f -a "keygen" -d 'Generate a private key, and print the public line for a peer'
complete -c vallum -n "__fish_vallum_using_subcommand help; and not __fish_seen_subcommand_from setup run keygen pubkey genpsk show setconf addconf syncconf showconf bench doctor server client join peer metrics identity import-bundle enroll-serve tui completions help" -f -a "pubkey" -d 'Print the public line for an existing private key'
complete -c vallum -n "__fish_vallum_using_subcommand help; and not __fish_seen_subcommand_from setup run keygen pubkey genpsk show setconf addconf syncconf showconf bench doctor server client join peer metrics identity import-bundle enroll-serve tui completions help" -f -a "genpsk" -d 'Generate a 32-byte preshared key as 64 hex characters'
complete -c vallum -n "__fish_vallum_using_subcommand help; and not __fish_seen_subcommand_from setup run keygen pubkey genpsk show setconf addconf syncconf showconf bench doctor server client join peer metrics identity import-bundle enroll-serve tui completions help" -f -a "show" -d 'Show a running daemon\'s device and peers'
complete -c vallum -n "__fish_vallum_using_subcommand help; and not __fish_seen_subcommand_from setup run keygen pubkey genpsk show setconf addconf syncconf showconf bench doctor server client join peer metrics identity import-bundle enroll-serve tui completions help" -f -a "setconf" -d 'Apply a configuration file, replacing every peer'
complete -c vallum -n "__fish_vallum_using_subcommand help; and not __fish_seen_subcommand_from setup run keygen pubkey genpsk show setconf addconf syncconf showconf bench doctor server client join peer metrics identity import-bundle enroll-serve tui completions help" -f -a "addconf" -d 'Add the peers from a configuration file'
complete -c vallum -n "__fish_vallum_using_subcommand help; and not __fish_seen_subcommand_from setup run keygen pubkey genpsk show setconf addconf syncconf showconf bench doctor server client join peer metrics identity import-bundle enroll-serve tui completions help" -f -a "syncconf" -d 'Apply only the differences between a config and the running daemon'
complete -c vallum -n "__fish_vallum_using_subcommand help; and not __fish_seen_subcommand_from setup run keygen pubkey genpsk show setconf addconf syncconf showconf bench doctor server client join peer metrics identity import-bundle enroll-serve tui completions help" -f -a "showconf" -d 'Export a running daemon as a config (secrets are not included)'
complete -c vallum -n "__fish_vallum_using_subcommand help; and not __fish_seen_subcommand_from setup run keygen pubkey genpsk show setconf addconf syncconf showconf bench doctor server client join peer metrics identity import-bundle enroll-serve tui completions help" -f -a "bench" -d 'Measure the data plane\'s seal/open cost on this host'
complete -c vallum -n "__fish_vallum_using_subcommand help; and not __fish_seen_subcommand_from setup run keygen pubkey genpsk show setconf addconf syncconf showconf bench doctor server client join peer metrics identity import-bundle enroll-serve tui completions help" -f -a "doctor" -d 'Check the platform, config, control socket, and helper tools'
complete -c vallum -n "__fish_vallum_using_subcommand help; and not __fish_seen_subcommand_from setup run keygen pubkey genpsk show setconf addconf syncconf showconf bench doctor server client join peer metrics identity import-bundle enroll-serve tui completions help" -f -a "server" -d 'Prepare this host to be a tunnel server'
complete -c vallum -n "__fish_vallum_using_subcommand help; and not __fish_seen_subcommand_from setup run keygen pubkey genpsk show setconf addconf syncconf showconf bench doctor server client join peer metrics identity import-bundle enroll-serve tui completions help" -f -a "client" -d 'Disconnect and remove a client tunnel installed by `vallum setup`'
complete -c vallum -n "__fish_vallum_using_subcommand help; and not __fish_seen_subcommand_from setup run keygen pubkey genpsk show setconf addconf syncconf showconf bench doctor server client join peer metrics identity import-bundle enroll-serve tui completions help" -f -a "join" -d 'Enrol this machine with the one-time ticket `vallum peer invite` printed'
complete -c vallum -n "__fish_vallum_using_subcommand help; and not __fish_seen_subcommand_from setup run keygen pubkey genpsk show setconf addconf syncconf showconf bench doctor server client join peer metrics identity import-bundle enroll-serve tui completions help" -f -a "peer" -d 'Enrol, list, inspect, and remove peers'
complete -c vallum -n "__fish_vallum_using_subcommand help; and not __fish_seen_subcommand_from setup run keygen pubkey genpsk show setconf addconf syncconf showconf bench doctor server client join peer metrics identity import-bundle enroll-serve tui completions help" -f -a "metrics" -d 'Print the daemon\'s state as Prometheus metrics'
complete -c vallum -n "__fish_vallum_using_subcommand help; and not __fish_seen_subcommand_from setup run keygen pubkey genpsk show setconf addconf syncconf showconf bench doctor server client join peer metrics identity import-bundle enroll-serve tui completions help" -f -a "identity" -d 'Issue, sign, verify, and inspect identity documents'
complete -c vallum -n "__fish_vallum_using_subcommand help; and not __fish_seen_subcommand_from setup run keygen pubkey genpsk show setconf addconf syncconf showconf bench doctor server client join peer metrics identity import-bundle enroll-serve tui completions help" -f -a "import-bundle" -d 'Import a client `.vallum-bundle` file'
complete -c vallum -n "__fish_vallum_using_subcommand help; and not __fish_seen_subcommand_from setup run keygen pubkey genpsk show setconf addconf syncconf showconf bench doctor server client join peer metrics identity import-bundle enroll-serve tui completions help" -f -a "enroll-serve" -d 'Answer token-gated enrolment requests (runs as its own service)'
complete -c vallum -n "__fish_vallum_using_subcommand help; and not __fish_seen_subcommand_from setup run keygen pubkey genpsk show setconf addconf syncconf showconf bench doctor server client join peer metrics identity import-bundle enroll-serve tui completions help" -f -a "tui" -d 'Operate a tunnel in a terminal dashboard'
complete -c vallum -n "__fish_vallum_using_subcommand help; and not __fish_seen_subcommand_from setup run keygen pubkey genpsk show setconf addconf syncconf showconf bench doctor server client join peer metrics identity import-bundle enroll-serve tui completions help" -f -a "completions" -d 'Print a shell completion script'
complete -c vallum -n "__fish_vallum_using_subcommand help; and not __fish_seen_subcommand_from setup run keygen pubkey genpsk show setconf addconf syncconf showconf bench doctor server client join peer metrics identity import-bundle enroll-serve tui completions help" -f -a "help" -d 'Print this message or the help of the given subcommand(s)'
complete -c vallum -n "__fish_vallum_using_subcommand help; and __fish_seen_subcommand_from server" -f -a "init" -d 'Generate the key, write the config, and start the service'
complete -c vallum -n "__fish_vallum_using_subcommand help; and __fish_seen_subcommand_from server" -f -a "enroll" -d 'Turn one-time token enrolment on or off, with its service and port'
complete -c vallum -n "__fish_vallum_using_subcommand help; and __fish_seen_subcommand_from server" -f -a "teardown" -d 'Undo the host changes `server init` made (units, NAT, firewall, sysctl)'
complete -c vallum -n "__fish_vallum_using_subcommand help; and __fish_seen_subcommand_from client" -f -a "teardown" -d 'Disconnect and remove a client tunnel installed by `vallum setup`'
complete -c vallum -n "__fish_vallum_using_subcommand help; and __fish_seen_subcommand_from peer" -f -a "add" -d 'Enrol a peer and optionally write its client bundle'
complete -c vallum -n "__fish_vallum_using_subcommand help; and __fish_seen_subcommand_from peer" -f -a "list" -d 'List the configured peers'
complete -c vallum -n "__fish_vallum_using_subcommand help; and __fish_seen_subcommand_from peer" -f -a "show" -d 'Show one peer'
complete -c vallum -n "__fish_vallum_using_subcommand help; and __fish_seen_subcommand_from peer" -f -a "remove" -d 'Remove a peer'
complete -c vallum -n "__fish_vallum_using_subcommand help; and __fish_seen_subcommand_from peer" -f -a "enroll" -d 'Enrol a device that generated its own key, and hand back its config'
complete -c vallum -n "__fish_vallum_using_subcommand help; and __fish_seen_subcommand_from peer" -f -a "invite" -d 'Mint a single-use token so a device can enrol without SSH access'
complete -c vallum -n "__fish_vallum_using_subcommand help; and __fish_seen_subcommand_from peer" -f -a "invites" -d 'List live one-time invites and their remaining TTL (pruning expired ones)'
complete -c vallum -n "__fish_vallum_using_subcommand help; and __fish_seen_subcommand_from peer" -f -a "rotate" -d 'Install a new identity while the old one keeps working'
complete -c vallum -n "__fish_vallum_using_subcommand help; and __fish_seen_subcommand_from peer" -f -a "finalize" -d 'Retire the previous identity a rotation kept'
complete -c vallum -n "__fish_vallum_using_subcommand help; and __fish_seen_subcommand_from identity" -f -a "issue" -d 'Issue a document signed by a CA key'
complete -c vallum -n "__fish_vallum_using_subcommand help; and __fish_seen_subcommand_from identity" -f -a "self-sign" -d 'Issue a document signed by the peer\'s own key'
complete -c vallum -n "__fish_vallum_using_subcommand help; and __fish_seen_subcommand_from identity" -f -a "verify" -d 'Check a document\'s signature and window'
complete -c vallum -n "__fish_vallum_using_subcommand help; and __fish_seen_subcommand_from identity" -f -a "show" -d 'Print a document\'s label, keys and window without verifying it'
