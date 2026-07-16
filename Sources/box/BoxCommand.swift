import ArgumentParser
import BoxKit

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
            Log.self, Doctor.self, Update.self, Version.self,
            Stop.self, Rm.self, Prune.self,
            Trust.self, Untrust.self,
            FsAllow.self, FsDeny.self, FsPolicy.self,
            Ca.self,
        ],
        defaultSubcommand: Run.self
    )
}

struct Run: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Launch Claude Code in the current directory (default).")

    @Argument(parsing: .captureForPassthrough, help: "Extra arguments passed to `claude`.")
    var args: [String] = []

    func run() async throws {
        let code = try await Commands.run(extraArgs: args)
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

struct FsAllow: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "fs-allow",
        abstract: "Make a subpath visible under the broad read-only root (live).")

    @Argument(help: "Path to allow.")
    var path: String

    func run() throws { try Commands.fsAllow(path: path) }
}

struct FsDeny: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "fs-deny",
        abstract: "Hide a subpath under the broad read-only root (live).")

    @Argument(help: "Path to deny.")
    var path: String

    func run() throws { try Commands.fsDeny(path: path) }
}

struct FsPolicy: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "fs-policy",
        abstract: "Show the current dynamic filesystem visibility policy.")

    func run() throws { try Commands.fsPolicy() }
}

struct Ca: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        abstract: "Manage the opt-in MITM CA used for path-level egress rules.",
        subcommands: [CaInit.self])
}

struct CaInit: AsyncParsableCommand {
    static let configuration = CommandConfiguration(
        commandName: "init",
        abstract: "Generate a CA in ~/.box/ca for squid to forge leaf certs.")

    func run() throws { try Commands.caInit() }
}
