import ArgumentParser
import BoxKit
import Foundation

@main
struct BoxCommand: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "box",
        abstract:
            "Run Claude Code in an Apple Containerization microVM with allowlist-only egress.",
        // `box --version`: box's own version, stamped from `git describe` via the
        // Makefile (`make version-stamp` → BoxKit.Version.box), else the in-file default.
        version: BoxKit.Version.box,
        subcommands: [
            Run.self, Shell.self, Exec.self, Login.self, Allow.self, Denied.self,
            Build.self, Ls.self, ConfigCmd.self,
            Log.self, Doctor.self, Update.self, Version.self, Completions.self,
            Stop.self, Rm.self, Prune.self,
            Trust.self, Untrust.self,
            Fs.self,
            Secret.self,
            Net.self, Resolver.self, NetProbeCmd.self,
            SystemCmd.self, DaemonRun.self,
        ],
        defaultSubcommand: Run.self
    )
}

struct Run: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Launch Claude Code in the current directory (default).")

    @Option(
        name: .customLong("allow-local"),
        help:
            "Open scoped egress from the box to a Mac-local port (repeatable), e.g. --allow-local 1433. Reachable in the box as host.box:<port>. Must precede any claude arguments.")
    var allowLocal: [String] = []

    @Flag(
        name: .customLong("devcontainer"),
        help:
            "Build on this project's .devcontainer base without trusting it first (auto-enabled when trusted).")
    var devcontainer = false

    @Argument(parsing: .captureForPassthrough, help: "Extra arguments passed to `claude`.")
    var args: [String] = []

    func run() async throws {
        let code = try await Commands.run(
            extraArgs: args, allowLocal: allowLocal, devcontainer: devcontainer)
        throw ExitCode(code)
    }
}

struct Shell: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Open a bash shell inside the box.",
        discussion: """
            If a box is already running for this directory, the shell opens inside \
            that same microVM (alongside the live Claude session). Use --new to \
            boot a separate VM instead.
            """)

    @Flag(name: .long, help: "Boot a separate VM even if a box is already running here.")
    var new = false

    @Argument(parsing: .captureForPassthrough)
    var args: [String] = []

    func run() async throws {
        let code = try await Commands.shell(extraArgs: args, new: new)
        throw ExitCode(code)
    }
}

struct Exec: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Run a command (default: a shell) inside a RUNNING box.")

    @Option(name: .long, help: "Target box id (default: the box running in this directory).")
    var box: String?

    @Argument(parsing: .captureForPassthrough, help: "Command to run (default: bash).")
    var command: [String] = []

    func run() throws {
        let code = try Commands.exec(box: box, command: command)
        throw ExitCode(code)
    }
}

struct Login: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Run Claude's interactive login (persisted in the agent home).")

    func run() async throws {
        let code = try await Commands.login()
        throw ExitCode(code)
    }
}

struct Allow: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Add domain(s) to the allowlist; running boxes reload automatically.",
        discussion: """
            With no domains, lists recently-denied hosts as a numbered menu and \
            promotes the ones you pick. Use --all (with --yes for non-interactive \
            shells) to promote every denied host as a wildcard.
            """)

    @Argument(help: "Domains to allow (leading dot = subdomains, e.g. .example.com).")
    var domains: [String] = []

    @Flag(name: .long, help: "Promote all recently-denied hosts (as wildcards).")
    var all = false
    @Flag(name: [.short, .long], help: "Assume yes; promote non-interactively.")
    var yes = false
    @Flag(
        name: .long, help: "Write to this project's .box/allowlist.txt instead of the global file.")
    var project = false

    func run() throws { try Commands.allow(domains, all: all, yes: yes, project: project) }
}

struct Denied: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Show recently blocked hosts and the sessions that hit them.")

    @Flag(
        name: [.customShort("i"), .long],
        help: "Interactively promote denied hosts into the allowlist.")
    var promote = false

    func run() throws {
        if promote {
            try Commands.promoteDenied()
            return
        }
        Commands.showDenied()
    }
}

struct Build: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Build the image (container build → OCI → framework store).")

    @Flag(name: .long, help: "Build without the layer cache.")
    var noCache = false

    func run() async throws { try await Commands.build(noCache: noCache) }
}

struct Ls: AsyncParsableCommand {
    static let configuration = CommandConfiguration(abstract: "List running boxes.")

    func run() throws {
        for box in Commands.listBoxes() { print("\(box.id)\t\(box.cwd)") }
    }
}

struct ConfigCmd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "config",
        abstract: "Show the resolved configuration and its file path.")

    func run() throws { Commands.showConfig() }
}

struct Log: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Show the egress audit log (allowed + denied requests).")

    @Flag(name: [.short, .long], help: "Follow the log as new entries arrive.")
    var follow = false
    @Flag(name: .long, help: "Show only denied (blocked) requests.")
    var denied = false
    @Option(name: .long, help: "Only entries since this time (e.g. 10m, 1h, an ISO date).")
    var since: String?
    @Option(name: .long, help: "Limit to a specific box id.")
    var box: String?
    @Flag(name: .long, help: "Aggregate across all boxes.")
    var all = false
    @Flag(name: .long, help: "Emit machine-readable JSON.")
    var json = false

    func run() throws {
        try Commands.log(
            follow: follow, denied: denied, since: since,
            box: box, all: all, json: json)
    }
}

struct Doctor: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Diagnose the host setup and box readiness.")

    @Flag(name: .long, help: "Also run checks that require network access.")
    var online = false
    @Flag(name: [.short, .long], help: "Show extra detail for each check.")
    var verbose = false

    func run() throws { try Commands.doctor(online: online, verbose: verbose) }
}

struct Update: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Rebuild the image with a newer Claude Code release.")

    @Option(name: .long, help: "Pin to a specific claude-code version (default: latest).")
    var to: String?

    func run() async throws { try await Commands.update(to: to) }
}

struct Version: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Print box, claude-code, containerization, and vminit versions.")

    @Flag(name: .long, help: "Query the live claude-code version (needs a running box).")
    var refresh = false

    func run() throws { try Commands.version(refresh: refresh) }
}

struct Completions: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "completions",
        abstract: "Print the shell completion script (bash, zsh, or fish).",
        discussion: """
            Prints to stdout by default. With --install, writes to the shell's \
            conventional completion directory (creating it as needed) and prints \
            the path.
            """)

    @Argument(help: "Shell to target — bash, zsh, or fish (default: from $SHELL).")
    var shell: String?

    @Flag(name: .long, help: "Install into the shell's completion directory instead of printing.")
    var install = false

    func run() throws {
        let target = try Commands.completionShell(
            argument: shell, shellEnv: ProcessInfo.processInfo.environment["SHELL"])
        let script = BoxCommand.completionScript(for: target.parserShell)
        guard install else {
            print(script, terminator: "")
            return
        }
        let path = try Commands.installCompletion(target, script: script)
        print("wrote \(path.path)")
        if target == .zsh, let hint = Commands.zshInstallHint() { print(hint) }
    }
}

extension BoxKit.CompletionShell {
    var parserShell: ArgumentParser.CompletionShell {
        switch self {
        case .bash: return .bash
        case .zsh: return .zsh
        case .fish: return .fish
        }
    }
}

struct Stop: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Stop a running box (graceful teardown).")

    @Argument(help: "The box id to stop.")
    var id: String
    @Flag(name: .long, help: "Force-kill instead of a graceful stop.")
    var kill = false

    func run() throws { try Commands.stop(id: id, kill: kill) }
}

struct Rm: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Stop (if running) and remove a box's state.")

    @Argument(help: "The box id to remove.")
    var id: String
    @Flag(name: .long, help: "Force-kill (SIGKILL) instead of a graceful stop.")
    var force = false

    func run() throws { try Commands.rm(id: id, force: force) }
}

struct Prune: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Remove stale box markers; optionally wipe persistent state.")

    @Flag(name: .long, help: "Also delete the persisted agent home.")
    var agentHome = false
    @Flag(name: .long, help: "Also delete the image store.")
    var store = false
    @Flag(name: .long, help: "Also delete box logs.")
    var logs = false
    @Flag(name: .long, help: "Delete all persistent state (agent home, store, logs).")
    var all = false
    @Flag(name: .long, help: "Skip the confirmation prompt.")
    var yes = false
    @Flag(name: .long, help: "Proceed even if boxes are still running.")
    var force = false

    func run() throws {
        try Commands.prune(
            agentHome: agentHome, store: store, logs: logs,
            all: all, yes: yes, force: force)
    }
}

struct Trust: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Approve this project's .box/ config for the current content.")

    @Flag(name: .long, help: "Trust only the project allowlist, not extraMounts/env.")
    var allowlistOnly = false
    @Flag(name: .long, help: "Show the current trust status instead of approving.")
    var show = false

    func run() throws { try Commands.trust(allowlistOnly: allowlistOnly, show: show) }
}

struct Untrust: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Revoke trust for this project's .box/ config.")

    func run() throws { try Commands.untrust() }
}

struct Fs: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "fs",
        abstract: "Show or hide subpaths of the broad read-only roots (live).",
        subcommands: [FsAllow.self, FsDeny.self, FsPolicy.self])
}

struct FsAllow: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "allow",
        abstract: "Make a subpath visible under the broad read-only root (live).")

    @Argument(help: "Path to allow.")
    var path: String

    func run() throws { try Commands.fsAllow(path: path) }
}

struct FsDeny: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "deny",
        abstract: "Hide a subpath under the broad read-only root (live).")

    @Argument(help: "Path to deny.")
    var path: String

    func run() throws { try Commands.fsDeny(path: path) }
}

struct FsPolicy: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "policy",
        abstract: "Show the current dynamic filesystem visibility policy.")

    func run() throws { try Commands.fsPolicy() }
}

struct Net: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Set up `.box` name resolution and look up box IPs.",
        subcommands: [NetInit.self, Ip.self])
}

struct NetInit: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "init",
        abstract: "Install /etc/resolver/box so <box-id>.box resolves on the Mac (needs sudo).")

    func run() throws { try Commands.netInit() }
}

struct Ip: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ip",
        abstract: "Print a running box's guest IP.")

    @Option(name: .long, help: "The box id (default: the box for this dir, or the only one).")
    var box: String?
    @Flag(name: .long, help: "List every running box (IP and <id>.box).")
    var all = false

    func run() throws { try Commands.boxIP(box: box, all: all) }
}

/// Hidden entry point for the singleton `.box` DNS resolver, spawned detached by
/// `box run`. Not shown in help.
struct Resolver: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "__resolver", shouldDisplay: false)

    func run() throws { try Commands.runResolver() }
}

struct SystemCmd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "system",
        abstract: "Manage the box daemon (required for `box run`).",
        discussion: """
            box runs egress through a daemon-owned Envoy proxy sidecar, shared by \
            all boxes with per-source isolation. Like `container system start`, \
            the daemon is a REQUIRED service you start explicitly — `box run` \
            errors if it's down (no auto-start, no fallback). Boxes attach at \
            launch; stopping the daemon leaves running boxes without egress until \
            restarted. (`dedicatedProxy` in config gives a box its own sidecar and \
            does not need the daemon.)
            """,
        subcommands: [SystemStart.self, SystemStop.self, SystemStatus.self])
}

struct SystemStart: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "start", abstract: "Start the box daemon and its shared Envoy sidecar.")

    func run() throws {
        if DaemonClient.isRunning() {
            print("box daemon: already running")
            return
        }
        print("box daemon: starting (booting the shared egress sidecar)…")
        try DaemonClient.start()
        print("box daemon: started")
    }
}

struct SystemStatus: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "status", abstract: "Show the daemon's sidecar and attached boxes.")

    func run() throws {
        let s: BoxKit.Daemon.Response
        do {
            s = try DaemonClient.status()
        } catch {
            print("box daemon: not running — start it with `box system start`")
            return
        }
        print("box daemon: running (version \(s.version ?? "?"))")
        print("  subnet:  \(s.subnet ?? "?")")
        print("  sidecar: \(s.sidecarIP ?? "?"):3128")
        let boxes = s.boxes ?? [:]
        print("  boxes:   \(boxes.isEmpty ? "none" : "")")
        for (id, ip) in boxes.sorted(by: { $0.key < $1.key }) {
            print("    \(id)\t\(ip)")
        }
    }
}

struct SystemStop: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "stop", abstract: "Stop the daemon and its shared sidecar.")

    @Flag(name: .long, help: "Stop even with boxes attached (their egress breaks).")
    var force = false

    func run() throws {
        let resp: BoxKit.Daemon.Response
        do {
            resp = try DaemonClient.stop(force: force)
        } catch {
            print("box daemon: not running")
            return
        }
        if resp.ok {
            print("box daemon: stopping")
        } else {
            print("box daemon: \(resp.error ?? "refused")")
            throw ExitCode(1)
        }
    }
}

/// Hidden entry point for the daemon process itself, spawned detached by the
/// first `box run` that needs it (or manually for debugging). Not shown in help.
struct DaemonRun: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "__daemon", shouldDisplay: false)

    func run() async throws { try await BoxKit.Daemon.run() }
}

/// Hidden diagnostic: probe direct guest→guest TCP on a shared VmnetNetwork
/// (decides whether split mode needs the host relay). See NetProbe.swift.
struct NetProbeCmd: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "__netprobe", shouldDisplay: false)

    @Flag(name: .long, help: "Inspect vmnet network serialization instead of the TCP probe.")
    var inspect = false
    @Flag(name: .long, help: "Cross-process probe: serve+join via a spawned child.")
    var cross = false
    @Option(name: .customLong("cross-serve"), help: "Internal: serve half, artifacts dir.")
    var crossServe: String?
    @Option(name: .customLong("cross-join"), help: "Internal: join half, artifacts dir.")
    var crossJoin: String?

    func run() async throws {
        if inspect {
            try NetProbe.inspectSerialization()
            return
        }
        if let dir = crossServe {
            try await NetProbeCross.serve(dir: dir)
            return
        }
        if let dir = crossJoin {
            throw ExitCode(try await NetProbeCross.join(dir: dir))
        }
        if cross {
            throw ExitCode(try await NetProbeCross.orchestrate())
        }
        let code = try await NetProbe.run()
        throw ExitCode(code)
    }
}

struct Secret: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Manage proxy-injected credentials Claude can use but never see.",
        discussion: """
            box injects a secret's value into matching requests at the egress proxy \
            (scoped by host and URL path), so Claude gets its use without its value. \
            The box-proxy sidecar decrypts allowlisted (non-pinned) hosts by default, \
            so no setup is needed; a box that defines secrets gets its own sidecar. \
            Projects can declare the secrets they need in .box/secrets.json; run \
            `box secret setup` to provide values.
            """,
        subcommands: [
            SecretSet.self, SecretSetup.self, SecretList.self, SecretShow.self, SecretRm.self,
        ])
}

struct SecretSet: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "set",
        abstract: "Define a secret and bind its value source (env var or Keychain).")

    @Argument(help: "Secret name (letters, digits, _ and -).")
    var name: String

    @Option(name: .customLong("from-env"), help: "Read the value from this host env var at launch.")
    var fromEnv: String?
    @Option(
        name: .customLong("from-keychain"),
        help: "Read from a Keychain generic password (service[/account]).")
    var fromKeychain: String?

    @Option(name: .customLong("as"), help: "Injection location: header | cookie | query.")
    var location: String = "header"
    @Option(
        name: .customLong("name"),
        help: "Field name (header/cookie/query-param). Default: Authorization.")
    var field: String?
    @Option(name: .long, help: "Value template, e.g. \"Bearer ${value}\" or \"${value|base64}\".")
    var template: String?

    @Option(name: .long, help: "Host to inject on (repeatable).")
    var host: [String] = []
    @Option(name: .customLong("path-prefix"), help: "Only inject on paths under this prefix.")
    var pathPrefix: String?
    @Option(name: .customLong("path-regex"), help: "Only inject on paths matching this regex.")
    var pathRegex: String?

    func run() throws {
        try Commands.secretSet(
            name: name, fromEnv: fromEnv, fromKeychain: fromKeychain,
            location: location, field: field, template: template,
            hosts: host, pathPrefix: pathPrefix, pathRegex: pathRegex)
    }
}

struct SecretSetup: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "setup",
        abstract: "Interactively provide values for any declared-but-unset secrets.")

    func run() throws { try Commands.secretSetup() }
}

struct SecretList: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "ls",
        abstract: "List defined secrets and their scopes (never values).")

    func run() throws { Commands.secretList() }
}

struct SecretShow: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "show",
        abstract: "Show one secret's injection spec and status (never its value).")

    @Argument(help: "Secret name.")
    var name: String

    func run() throws { try Commands.secretShow(name: name) }
}

struct SecretRm: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "rm",
        abstract: "Remove a global secret (requirement + binding).")

    @Argument(help: "Secret name.")
    var name: String

    func run() throws { try Commands.secretRemove(name: name) }
}
