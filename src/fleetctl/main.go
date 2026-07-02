// SPDX-License-Identifier: MIT
// Copyright (C) 2026 Szymon Wilczek
// LOTA Fleet CLI - lota-fleet
//
// Command-line front end for the verifier's REST monitoring API.
//
// One binary covers the fleet lifecycle operator otherwise drives with
// curl: device inventory, revocations, hardware bans, forced re-anchor,
// client removal, LFA re-anchor review, audit and attestation logs,
// and session-token validation.
//
// Connection:
//
//	--server URL            or LOTA_FLEET_SERVER (default http://127.0.0.1:8080)
//	--key-file PATH         or LOTA_FLEET_API_KEY (reader or admin Bearer key)
//	--tls-ca PATH           extra TLS root for an https --server
//
// The API key is never taken from argv, so it cannot leak through the
// process list; pass a file or the environment variable.

package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/szymonwilczek/lota/fleetctl/client"
)

const (
	envServer = "LOTA_FLEET_SERVER"
	envAPIKey = "LOTA_FLEET_API_KEY" // #nosec G101 -- variable name, not a credential

	defaultServer = "http://127.0.0.1:8080"
)

const usageText = `Usage: lota-fleet [global flags] <command> [command flags] [args]

Fleet operations against a LOTA verifier monitoring API.

Global flags:
  -server URL     API base URL (or ` + envServer + `; default ` + defaultServer + `)
  -key-file PATH  file holding the Bearer API key (or ` + envAPIKey + `)
  -tls-ca PATH    PEM roots to trust for an https -server
  -timeout DUR    per-request timeout (default 30s)
  -json           print raw API responses as JSON

Commands:
  health                                  verifier health check
  stats                                   verification statistics
  devices list [-limit N] [-offset N]     list registered client IDs
  devices show <client-id>                per-client details
  revoke <client-id> -reason R -actor A [-note S]
                                          revoke a client's AIK
  unrevoke <client-id>                    lift a revocation
  revocations                             list active revocations
  ban <hardware-id> -reason R -actor A [-note S]
                                          ban a hardware identity
  unban <hardware-id>                     lift a hardware ban
  bans [-limit N] [-next-id CURSOR]       list active hardware bans
  reanchor <client-id> -actor A [-note S] force a baseline re-anchor
  delete <client-id> [-actor A] [-note S] remove a client's trust state
  reanchor-review list                    clients awaiting LFA review
  reanchor-review ack <client-id>         acknowledge an LFA re-anchor
  audit [-limit N]                        operator audit log
  attests [-limit N]                      attestation decision log
  session validate <token> [-consume]     validate a session token

Revocation and ban reasons: cheating, compromised, hardware_change, admin.
`

// exit codes:
// 0 success,
// 1 operation failed or reported a negative result (degraded health, invalid token),
// 2 usage error
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, os.Getenv))
}

// cmdContext carries everything one command handler needs.
type cmdContext struct {
	api    *client.Client
	stdout io.Writer
	asJSON bool
}

func run(argv []string, stdout, stderr io.Writer, getenv func(string) string) int {
	global := flag.NewFlagSet("lota-fleet", flag.ContinueOnError)
	global.SetOutput(stderr)
	global.Usage = func() { fmt.Fprint(stderr, usageText) }

	serverFlag := global.String("server", "", "API base URL")
	keyFile := global.String("key-file", "", "file holding the Bearer API key")
	tlsCA := global.String("tls-ca", "", "PEM roots to trust for an https server")
	timeout := global.Duration("timeout", 30*time.Second, "per-request timeout")
	asJSON := global.Bool("json", false, "print raw API responses as JSON")

	if err := global.Parse(argv); err != nil {
		return exitUsage
	}

	args := global.Args()
	if len(args) == 0 {
		global.Usage()
		return exitUsage
	}

	server := *serverFlag
	if server == "" {
		server = getenv(envServer)
	}
	if server == "" {
		server = defaultServer
	}

	apiKey := getenv(envAPIKey)
	if *keyFile != "" {
		raw, err := os.ReadFile(*keyFile)
		if err != nil {
			fmt.Fprintf(stderr, "lota-fleet: reading key file: %v\n", err)
			return exitError
		}
		apiKey = strings.TrimSpace(string(raw))
	}

	var caPEM []byte
	if *tlsCA != "" {
		raw, err := os.ReadFile(*tlsCA)
		if err != nil {
			fmt.Fprintf(stderr, "lota-fleet: reading TLS CA file: %v\n", err)
			return exitError
		}
		caPEM = raw
	}

	api, err := client.New(client.Config{
		ServerURL: server,
		APIKey:    apiKey,
		CACertPEM: caPEM,
		Timeout:   *timeout,
	})
	if err != nil {
		fmt.Fprintf(stderr, "lota-fleet: %v\n", err)
		return exitError
	}

	ctx := &cmdContext{api: api, stdout: stdout, asJSON: *asJSON}

	code, err := dispatch(ctx, stderr, args[0], args[1:])
	if err != nil {
		fmt.Fprintf(stderr, "lota-fleet: %v\n", err)
	}
	return code
}

// errUsage marks command-level argument mistakes
// so dispatch can map them onto the usage exit code.
var errUsage = errors.New("usage error")

func dispatch(ctx *cmdContext, stderr io.Writer, cmd string, args []string) (int, error) {
	var err error
	switch cmd {
	case "health":
		return cmdHealth(ctx, args)
	case "stats":
		err = cmdStats(ctx, args)
	case "devices":
		err = cmdDevices(ctx, stderr, args)
	case "revoke":
		err = cmdRevoke(ctx, stderr, args)
	case "unrevoke":
		err = cmdUnrevoke(ctx, args)
	case "revocations":
		err = cmdRevocations(ctx, args)
	case "ban":
		err = cmdBan(ctx, stderr, args)
	case "unban":
		err = cmdUnban(ctx, args)
	case "bans":
		err = cmdBans(ctx, stderr, args)
	case "reanchor":
		err = cmdReanchor(ctx, stderr, args)
	case "delete":
		err = cmdDelete(ctx, stderr, args)
	case "reanchor-review":
		err = cmdReanchorReview(ctx, args)
	case "audit":
		err = cmdAudit(ctx, stderr, args)
	case "attests":
		err = cmdAttests(ctx, stderr, args)
	case "session":
		return cmdSession(ctx, stderr, args)
	default:
		return exitUsage, fmt.Errorf("unknown command %q (see lota-fleet -h)", cmd)
	}

	switch {
	case err == nil:
		return exitOK, nil
	case errors.Is(err, errUsage):
		return exitUsage, err
	default:
		return exitError, err
	}
}

// printJSON renders any API response struct as indented JSON.
func printJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// kv prints one "key: value" detail line, skipping empty values.
func kv(w io.Writer, key string, value any) {
	if s, ok := value.(string); ok && s == "" {
		return
	}
	fmt.Fprintf(w, "%s: %v\n", key, value)
}

func cmdHealth(ctx *cmdContext, args []string) (int, error) {
	if len(args) != 0 {
		return exitUsage, fmt.Errorf("%w: health takes no arguments", errUsage)
	}

	h, err := ctx.api.Health()
	if err != nil {
		return exitError, err
	}

	if ctx.asJSON {
		if err := printJSON(ctx.stdout, h); err != nil {
			return exitError, err
		}
	} else {
		kv(ctx.stdout, "status", h.Status)
		kv(ctx.stdout, "uptime", h.Uptime)
		fmt.Fprintf(ctx.stdout, "tls listening: %v (%s)\n", h.TLS.Listening, h.TLS.Address)
	}

	// degraded verifier is failed check for scripts
	if h.Status != "ok" {
		return exitError, nil
	}
	return exitOK, nil
}

func cmdStats(ctx *cmdContext, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("%w: stats takes no arguments", errUsage)
	}

	s, err := ctx.api.Stats()
	if err != nil {
		return err
	}
	if ctx.asJSON {
		return printJSON(ctx.stdout, s)
	}

	kv(ctx.stdout, "registered clients", s.RegisteredClients)
	kv(ctx.stdout, "active policy", s.ActivePolicy)
	kv(ctx.stdout, "loaded policies", strings.Join(s.LoadedPolicies, ", "))
	kv(ctx.stdout, "total attestations", s.TotalAttestations)
	kv(ctx.stdout, "successful", s.SuccessfulAttests)
	kv(ctx.stdout, "failed", s.FailedAttests)
	kv(ctx.stdout, "revoked", s.RevokedAttests)
	kv(ctx.stdout, "banned", s.BannedAttests)
	kv(ctx.stdout, "active revocations", s.ActiveRevocations)
	kv(ctx.stdout, "active bans", s.ActiveBans)
	kv(ctx.stdout, "pending challenges", s.PendingChallenges)
	kv(ctx.stdout, "used nonces", s.UsedNonces)
	kv(ctx.stdout, "uptime", s.Uptime)
	return nil
}

func cmdDevices(ctx *cmdContext, stderr io.Writer, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: devices needs a subcommand (list, show)", errUsage)
	}

	switch args[0] {
	case "list":
		fs := flag.NewFlagSet("devices list", flag.ContinueOnError)
		fs.SetOutput(stderr)
		limit := fs.Int("limit", 0, "page size (server default 100)")
		offset := fs.Int("offset", 0, "page start")
		if err := fs.Parse(args[1:]); err != nil {
			return errUsage
		}

		page, err := ctx.api.ListClients(*limit, *offset)
		if err != nil {
			return err
		}
		if ctx.asJSON {
			return printJSON(ctx.stdout, page)
		}
		for _, id := range page.Clients {
			fmt.Fprintln(ctx.stdout, id)
		}
		fmt.Fprintf(stderr, "%d of %d clients (limit %d, offset %d)\n",
			page.Count, page.Total, page.Limit, page.Offset)
		return nil

	case "show":
		if len(args) != 2 {
			return fmt.Errorf("%w: devices show needs exactly one client ID", errUsage)
		}

		info, err := ctx.api.ClientInfo(args[1])
		if err != nil {
			return err
		}
		if ctx.asJSON {
			return printJSON(ctx.stdout, info)
		}
		kv(ctx.stdout, "client", info.ClientID)
		kv(ctx.stdout, "hardware id", info.HardwareID)
		kv(ctx.stdout, "revoked", info.Revoked)
		kv(ctx.stdout, "revocation reason", info.RevocationReason)
		kv(ctx.stdout, "first seen", info.FirstSeen)
		kv(ctx.stdout, "last attestation", info.LastAttestation)
		kv(ctx.stdout, "attestation count", info.AttestCount)
		kv(ctx.stdout, "monotonic counter", info.MonotonicCounter)
		kv(ctx.stdout, "pending challenges", info.PendingChallenges)
		kv(ctx.stdout, "pcr14 baseline", info.PCR14Baseline)
		return nil

	default:
		return fmt.Errorf("%w: unknown devices subcommand %q", errUsage, args[0])
	}
}

// parseActionArgs handles the shared "<id> -actor A [-note S] [-reason R]"
// argument shape of the mutating commands.
func parseActionArgs(name string, stderr io.Writer, args []string, needReason, needActor bool) (id, reason, actor, note string, err error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	reasonF := fs.String("reason", "", "revocation reason")
	actorF := fs.String("actor", "", "administrator identifier for the audit log")
	noteF := fs.String("note", "", "free-form justification")

	if len(args) == 0 {
		return "", "", "", "", fmt.Errorf("%w: %s needs a target argument", errUsage, name)
	}
	if err := fs.Parse(args[1:]); err != nil {
		return "", "", "", "", errUsage
	}
	if fs.NArg() != 0 {
		return "", "", "", "", fmt.Errorf("%w: %s takes one target argument", errUsage, name)
	}
	if needReason && *reasonF == "" {
		return "", "", "", "", fmt.Errorf("%w: %s requires -reason", errUsage, name)
	}
	if needActor && *actorF == "" {
		return "", "", "", "", fmt.Errorf("%w: %s requires -actor", errUsage, name)
	}
	return args[0], *reasonF, *actorF, *noteF, nil
}

func cmdRevoke(ctx *cmdContext, stderr io.Writer, args []string) error {
	id, reason, actor, note, err := parseActionArgs("revoke", stderr, args, true, true)
	if err != nil {
		return err
	}
	if err := ctx.api.Revoke(id, reason, actor, note); err != nil {
		return err
	}
	fmt.Fprintf(ctx.stdout, "revoked %s (%s)\n", id, reason)
	return nil
}

func cmdUnrevoke(ctx *cmdContext, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("%w: unrevoke needs exactly one client ID", errUsage)
	}
	if err := ctx.api.Unrevoke(args[0]); err != nil {
		return err
	}
	fmt.Fprintf(ctx.stdout, "unrevoked %s\n", args[0])
	return nil
}

func cmdRevocations(ctx *cmdContext, args []string) error {
	if len(args) != 0 {
		return fmt.Errorf("%w: revocations takes no arguments", errUsage)
	}

	revs, err := ctx.api.ListRevocations()
	if err != nil {
		return err
	}
	if ctx.asJSON {
		return printJSON(ctx.stdout, revs)
	}

	tw := tabwriter.NewWriter(ctx.stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "CLIENT\tREASON\tREVOKED AT\tBY\tNOTE")
	for _, r := range revs {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			r.ClientID, r.Reason, r.RevokedAt, r.RevokedBy, r.Note)
	}
	return tw.Flush()
}

func cmdBan(ctx *cmdContext, stderr io.Writer, args []string) error {
	hwid, reason, actor, note, err := parseActionArgs("ban", stderr, args, true, true)
	if err != nil {
		return err
	}
	if err := ctx.api.Ban(hwid, reason, actor, note); err != nil {
		return err
	}
	fmt.Fprintf(ctx.stdout, "banned %s (%s)\n", hwid, reason)
	return nil
}

func cmdUnban(ctx *cmdContext, args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("%w: unban needs exactly one hardware ID", errUsage)
	}
	if err := ctx.api.Unban(args[0]); err != nil {
		return err
	}
	fmt.Fprintf(ctx.stdout, "unbanned %s\n", args[0])
	return nil
}

func cmdBans(ctx *cmdContext, stderr io.Writer, args []string) error {
	fs := flag.NewFlagSet("bans", flag.ContinueOnError)
	fs.SetOutput(stderr)
	limit := fs.Int("limit", 0, "page size (server default 100)")
	nextID := fs.String("next-id", "", "cursor from the previous page")
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("%w: bans takes no positional arguments", errUsage)
	}

	page, err := ctx.api.ListBans(*limit, *nextID)
	if err != nil {
		return err
	}
	if ctx.asJSON {
		return printJSON(ctx.stdout, page)
	}

	tw := tabwriter.NewWriter(ctx.stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "HARDWARE ID\tREASON\tBANNED AT\tBY\tNOTE")
	for _, b := range page.Bans {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			b.HardwareID, b.Reason, b.BannedAt, b.BannedBy, b.Note)
	}
	if err := tw.Flush(); err != nil {
		return err
	}
	if page.NextID != "" {
		fmt.Fprintf(stderr, "more results: -next-id %s\n", page.NextID)
	}
	return nil
}

func cmdReanchor(ctx *cmdContext, stderr io.Writer, args []string) error {
	id, _, actor, note, err := parseActionArgs("reanchor", stderr, args, false, true)
	if err != nil {
		return err
	}
	if err := ctx.api.Reanchor(id, actor, note); err != nil {
		return err
	}
	fmt.Fprintf(ctx.stdout, "reanchored %s: baselines cleared, next attestation re-establishes trust\n", id)
	return nil
}

func cmdDelete(ctx *cmdContext, stderr io.Writer, args []string) error {
	id, _, actor, note, err := parseActionArgs("delete", stderr, args, false, false)
	if err != nil {
		return err
	}
	if err := ctx.api.DeleteClient(id, actor, note); err != nil {
		return err
	}
	fmt.Fprintf(ctx.stdout, "deleted %s: trust state removed, revocations and bans kept\n", id)
	return nil
}

func cmdReanchorReview(ctx *cmdContext, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("%w: reanchor-review needs a subcommand (list, ack)", errUsage)
	}

	switch args[0] {
	case "list":
		if len(args) != 1 {
			return fmt.Errorf("%w: reanchor-review list takes no arguments", errUsage)
		}
		clients, err := ctx.api.ReanchorReviewList()
		if err != nil {
			return err
		}
		if ctx.asJSON {
			return printJSON(ctx.stdout, clients)
		}
		for _, id := range clients {
			fmt.Fprintln(ctx.stdout, id)
		}
		return nil

	case "ack":
		if len(args) != 2 {
			return fmt.Errorf("%w: reanchor-review ack needs exactly one client ID", errUsage)
		}
		if err := ctx.api.ReanchorReviewAck(args[1]); err != nil {
			return err
		}
		fmt.Fprintf(ctx.stdout, "reviewed %s\n", args[1])
		return nil

	default:
		return fmt.Errorf("%w: unknown reanchor-review subcommand %q", errUsage, args[0])
	}
}

// parseLimit handles the shared "[-limit N]" shape of the log commands.
func parseLimit(name string, stderr io.Writer, args []string) (int, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(stderr)
	limit := fs.Int("limit", 0, "number of entries (server default 100)")
	if err := fs.Parse(args); err != nil {
		return 0, errUsage
	}
	if fs.NArg() != 0 {
		return 0, fmt.Errorf("%w: %s takes no positional arguments", errUsage, name)
	}
	return *limit, nil
}

func cmdAudit(ctx *cmdContext, stderr io.Writer, args []string) error {
	limit, err := parseLimit("audit", stderr, args)
	if err != nil {
		return err
	}

	entries, err := ctx.api.Audit(limit)
	if err != nil {
		return err
	}
	if ctx.asJSON {
		return printJSON(ctx.stdout, entries)
	}

	tw := tabwriter.NewWriter(ctx.stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tACTION\tTARGET\tACTOR\tREASON\tNOTE")
	for _, e := range entries {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\t%s\n",
			e.Timestamp, e.Action, e.TargetID, e.Actor, e.Reason, e.Note)
	}
	return tw.Flush()
}

func cmdAttests(ctx *cmdContext, stderr io.Writer, args []string) error {
	limit, err := parseLimit("attests", stderr, args)
	if err != nil {
		return err
	}

	entries, err := ctx.api.Attestations(limit)
	if err != nil {
		return err
	}
	if ctx.asJSON {
		return printJSON(ctx.stdout, entries)
	}

	tw := tabwriter.NewWriter(ctx.stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "TIME\tCLIENT\tRESULT\tMS\tDETAILS")
	for i := range entries {
		e := &entries[i]
		fmt.Fprintf(tw, "%s\t%s\t%s\t%.1f\t%s\n",
			e.Timestamp, e.ClientID, e.Result, e.DurationMs, e.Details)
	}
	return tw.Flush()
}

func cmdSession(ctx *cmdContext, stderr io.Writer, args []string) (int, error) {
	if len(args) == 0 || args[0] != "validate" {
		return exitUsage, fmt.Errorf("%w: session needs the validate subcommand", errUsage)
	}

	fs := flag.NewFlagSet("session validate", flag.ContinueOnError)
	fs.SetOutput(stderr)
	consume := fs.Bool("consume", false, "mark the token used so it cannot validate again")
	if len(args) < 2 {
		return exitUsage, fmt.Errorf("%w: session validate needs a token argument", errUsage)
	}
	if err := fs.Parse(args[2:]); err != nil {
		return exitUsage, errUsage
	}

	status, err := ctx.api.ValidateSessionToken(args[1], *consume)
	if err != nil {
		return exitError, err
	}

	if ctx.asJSON {
		if err := printJSON(ctx.stdout, status); err != nil {
			return exitError, err
		}
	} else {
		kv(ctx.stdout, "valid", status.Valid)
		kv(ctx.stdout, "consumed", status.Consumed)
		kv(ctx.stdout, "client", status.ClientID)
		kv(ctx.stdout, "hardware id", status.HardwareID)
	}

	// invalid token is failed check for scripts
	if !status.Valid {
		return exitError, nil
	}
	return exitOK, nil
}
