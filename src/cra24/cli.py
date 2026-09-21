# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 cra24 contributors
"""Command line interface.

This is the only module allowed to exit the process or print to stdout. Everything
below it raises :class:`~cra24.errors.Cra24Error` and returns data, so the same
code path serves the CLI, the watch daemon and the service.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any

from . import DISCLAIMER, __version__
from . import config as config_mod
from . import evidence as evidence_mod
from . import logging as log_mod
from .clock import Track, timeline
from .emit import csaf as csaf_mod
from .emit import srp as srp_mod
from .emit import validate as validate_mod
from .emit import vex as vex_mod
from .errors import ConfigError, Cra24Error, DossierIncomplete
from .evidence import Ledger
from .feeds import Cache, FeedSet
from .feeds.registry import ALL_FEEDS, best_component
from .ingest import load_buildroot, load_sbom, load_yocto
from .model import Product
from .triage import Confidence, triage

STAGES = ("early_warning", "notification", "final_report")


# --------------------------------------------------------------------------
# presentation
# --------------------------------------------------------------------------


def _colour_enabled(stream=sys.stdout) -> bool:
    if os.environ.get("NO_COLOR") is not None:
        return False
    if os.environ.get("CRA24_FORCE_COLOR"):
        return True
    return hasattr(stream, "isatty") and stream.isatty()


class Style:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def _wrap(self, code: str, text: str) -> str:
        return f"\033[{code}m{text}\033[0m" if self.enabled else text

    def bold(self, t: str) -> str:
        return self._wrap("1", t)

    def dim(self, t: str) -> str:
        return self._wrap("2", t)

    def red(self, t: str) -> str:
        return self._wrap("31", t)

    def green(self, t: str) -> str:
        return self._wrap("32", t)

    def yellow(self, t: str) -> str:
        return self._wrap("33", t)

    def status(self, value: str) -> str:
        return {
            "affected": self.red,
            "overdue": self.red,
            "under_investigation": self.yellow,
            "due-soon": self.yellow,
            "not_affected": self.green,
            "fixed": self.green,
            "submitted": self.green,
        }.get(value, lambda t: t)(value)


# --------------------------------------------------------------------------
# shared loading
# --------------------------------------------------------------------------


def _load_product(args: argparse.Namespace) -> Product:
    sources = [
        bool(args.product),
        bool(args.build_dir),
        bool(getattr(args, "buildroot_dir", None)),
        bool(args.sbom),
    ]
    if sum(sources) > 1:
        raise ConfigError(
            "give exactly one of --product, --build-dir, --buildroot-dir or --sbom"
        )
    if args.product:
        product = Product.load(args.product)
    elif args.build_dir:
        product = load_yocto(
            args.build_dir,
            machine=args.machine,
            kernel_config=args.kernel_config,
            include_unshipped=getattr(args, "include_unshipped", False),
        )
    elif getattr(args, "buildroot_dir", None):
        product = load_buildroot(args.buildroot_dir, kernel_config=args.kernel_config)
    elif args.sbom:
        product = load_sbom(args.sbom, kernel_config=args.kernel_config)
    else:
        raise ConfigError(
            "no inventory source given",
            hint="pass --build-dir for Yocto, --buildroot-dir for Buildroot, "
            "--sbom for a CycloneDX or SPDX file, or --product for a previous scan",
        )
    if getattr(args, "config", None):
        config_mod.load(product, args.config)
    return product


def _feed_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("vulnerability feeds")
    group.add_argument(
        "--feeds",
        nargs="?",
        const="all",
        metavar="LIST",
        help="consult the feeds, fetching if the cache is stale. "
        f"Comma-separated, or 'all' ({', '.join(ALL_FEEDS)}). "
        "Without this flag cra24 uses an existing cache but never opens a socket.",
    )
    group.add_argument(
        "--no-feeds", action="store_true", help="ignore feed data entirely, even a cached copy"
    )
    group.add_argument(
        "--offline",
        action="store_true",
        help="never open a socket; answer from the cache and say how old it is",
    )
    group.add_argument(
        "--cache-dir",
        metavar="DIR",
        help="where cached feed data lives (default .cra24-cache, or $CRA24_CACHE_DIR)",
    )


def _feedset(args: argparse.Namespace) -> FeedSet | None:
    """Build the feed set for this run, or None when feeds are not in play.

    The default is deliberate: an existing cache is used, and no socket is
    opened. Reading a file you already have is not a network call, and a triage
    run that silently reached out to the internet would be one you could not
    reproduce later.
    """
    if getattr(args, "no_feeds", False):
        return None
    requested = getattr(args, "feeds", None)
    names = ALL_FEEDS
    if requested and requested != "all":
        names = tuple(n.strip() for n in requested.split(",") if n.strip())

    offline = getattr(args, "offline", False) or not requested
    feeds = FeedSet(names, cache=Cache(getattr(args, "cache_dir", None)), offline=offline)

    if offline and not any(s.present for s in feeds.status()):
        return None
    return feeds


def _enrich(args: argparse.Namespace, product: Product, cve: str):
    feeds = _feedset(args)
    if feeds is None:
        return None
    return feeds.enrich(cve, best_component(product, cve))


def _source_args(parser: argparse.ArgumentParser) -> None:
    group = parser.add_argument_group("inventory source")
    group.add_argument(
        "--build-dir", metavar="DIR", help="Yocto build directory (the one containing tmp/)"
    )
    group.add_argument("--machine", help="restrict to one MACHINE under tmp/deploy/images")
    group.add_argument(
        "--buildroot-dir",
        metavar="DIR",
        help="Buildroot output directory (the one containing legal-info/)",
    )
    group.add_argument("--sbom", metavar="FILE", help="CycloneDX or SPDX JSON")
    group.add_argument(
        "--product", metavar="FILE", help="product.json written by a previous scan"
    )
    group.add_argument(
        "--config",
        metavar="FILE",
        help="JSON or TOML file with manufacturer and product identity",
    )
    group.add_argument(
        "--kernel-config",
        metavar="FILE",
        help="kernel .config for gating (auto-detected when omitted)",
    )


# --------------------------------------------------------------------------
# commands
# --------------------------------------------------------------------------


def cmd_init(args: argparse.Namespace) -> int:
    out = Path(args.out or "cra24.json")
    if out.exists() and not args.force:
        raise ConfigError(f"{out} already exists", hint="pass --force to overwrite")
    out.write_text(
        json.dumps(config_mod.template(args.name, args.product_version), indent=2) + "\n",
        encoding="utf-8",
    )
    style = Style(_colour_enabled())
    print(f"wrote {out}")
    print()
    print(style.bold("Fill these in before an incident, not during one:"))
    print("  manufacturer.name, .country, .contact_email")
    print(
        "  manufacturer.coordinator_csirt   — fixed by your Member State of main establishment"
    )
    print("  manufacturer.assigned_representative — needs a working EU Login account with MFA")
    print("  member_states                    — where the product is made available")
    print()
    print(style.dim("Registration on the SRP cannot be done retroactively."))
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    product = _load_product(args)
    out = Path(args.out or "product.json")
    product.save(out)
    counts = product.counts()
    style = Style(_colour_enabled())

    print(f"{counts['components']} components -> {out}")
    print(
        f"  {style.red(str(counts['unpatched']) + ' unpatched')}, "
        f"{counts['patched']} patched, {counts['ignored']} ignored, "
        f"{counts['unknown']} unknown"
    )
    if product.kernel_config:
        print(
            f"  {len(product.kernel_config)} kernel config symbols read (available for gating)"
        )
    else:
        print(
            style.dim(
                "  no kernel .config found — config gating is off; "
                "pass --kernel-config to enable it"
            )
        )

    gaps = product.validate()
    if gaps:
        print()
        print(style.yellow(f"{len(gaps)} reporting field(s) still unset:"))
        for gap in gaps:
            print(f"  - {gap}")
        print(style.dim("  supply them with --config; run `cra24 init` for a template"))
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    product = _load_product(args)
    enrichment = _enrich(args, product, args.cve)
    result = triage(
        product,
        args.cve,
        actively_exploited=_tristate(args.actively_exploited),
        advisory_fixed_version=args.fixed_version,
        gate_symbols=_gate_symbols(args),
        enrichment=enrichment,
    )
    style = Style(_colour_enabled())

    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
        return 0

    print(
        f"{style.bold(result.cve)} in {product.name} {product.version}: "
        f"{style.status(result.status.value)}"
    )
    print()
    for comp in result.components:
        marker = {
            Confidence.HIGH: "",
            Confidence.MEDIUM: " (medium confidence)",
            Confidence.LOW: " (low confidence)",
        }[comp.confidence]
        print(f"  {comp.component} {comp.version} -> {style.status(comp.status.value)}{marker}")
        if comp.justification:
            print(f"    justification: {comp.justification.value}")
        for finding in comp.findings:
            print(style.dim(f"    · {finding.rule}: {finding.conclusion}"))
            if finding.evidence and args.verbose:
                print(style.dim(f"      {finding.evidence}"))
    if not result.components:
        print(style.dim("  no component in this image carries it"))
    if enrichment is not None and enrichment.evidence:
        print()
        print(style.bold("feeds"))
        for item in enrichment.evidence:
            print(f"  {item.source}: {item.statement}")
            if item.detail and args.verbose:
                print(style.dim(f"    {item.detail}"))
        if enrichment.offline:
            print(style.dim("  (offline — answered from the cache)"))

    print()
    print(result.summary)
    if result.reportable_reason:
        print(
            ("REPORTABLE — " if result.reportable else "not reportable — ")
            + result.reportable_reason
        )
    if result.requires_human:
        print(style.yellow("a human decision is still required on at least one component"))
    return 0


def _gate_symbols(args: argparse.Namespace) -> list[str] | None:
    """Kernel config symbols that gate the vulnerable code for this CVE."""
    raw = getattr(args, "gate", None)
    if not raw:
        return None
    symbols: list[str] = []
    for chunk in raw:
        symbols.extend(s.strip().upper() for s in chunk.split(",") if s.strip())
    return [s if s.startswith("CONFIG_") else f"CONFIG_{s}" for s in symbols]


def _tristate(value: str | None) -> bool | None:
    if value is None:
        return None
    return {"yes": True, "true": True, "no": False, "false": False}.get(value.lower())


def _answers_from(args: argparse.Namespace) -> dict[str, Any]:
    answers: dict[str, Any] = {}
    for pair in args.field or []:
        if "=" not in pair:
            raise ConfigError(f"--field expects key=value, got {pair!r}")
        key, _, value = pair.partition("=")
        answers[key.strip()] = value
    if args.answers:
        answers.update(config_mod.load_raw(args.answers))
    for key, value in (
        ("severity", args.severity),
        ("malicious_intent", args.malicious_intent),
        ("cross_border", args.cross_border),
        ("summary", args.summary),
    ):
        if value:
            answers[key] = value
    return answers


def cmd_report(args: argparse.Namespace) -> int:
    product = _load_product(args)
    style = Style(_colour_enabled())
    track = Track(args.track)

    enrichment = _enrich(args, product, args.cve)
    result = triage(
        product,
        args.cve,
        actively_exploited=_tristate(args.actively_exploited),
        advisory_fixed_version=args.fixed_version,
        gate_symbols=_gate_symbols(args),
        enrichment=enrichment,
    )

    dossier = srp_mod.build(
        product,
        result,
        args.aware_at,
        stage=args.stage,
        track=track,
        answers=_answers_from(args),
        measure_available_at=args.measure_available,
    )

    outdir = Path(args.out or "dossier")
    outdir.mkdir(parents=True, exist_ok=True)
    slug = args.cve.lower().replace("/", "-")
    written: list[Path] = []

    def write(path: Path, payload: str) -> None:
        path.write_text(payload, encoding="utf-8")
        written.append(path)

    write(
        outdir / f"{slug}-{args.stage.replace('_', '-')}.json",
        json.dumps(dossier.to_dict(), indent=2, sort_keys=True) + "\n",
    )
    write(outdir / f"{slug}-{args.stage.replace('_', '-')}.md", srp_mod.to_markdown(dossier))

    tid = args.tracking_id or csaf_mod.tracking_id(product, args.cve)
    advisory = csaf_mod.build(product, result, tid, version=str(args.doc_version), tlp=args.tlp)
    vex_id = args.vex_id or vex_mod.document_id(product, args.cve, version=args.doc_version)
    vex_doc = vex_mod.build(product, result, vex_id, version=args.doc_version)

    if not args.no_validate:
        validate_mod.validate_csaf(advisory)
        validate_mod.validate_openvex(vex_doc)

    write(outdir / f"{slug}.csaf.json", json.dumps(advisory, indent=2, sort_keys=True) + "\n")
    write(outdir / f"{slug}.openvex.json", json.dumps(vex_doc, indent=2, sort_keys=True) + "\n")

    ledger = Ledger(args.evidence or (outdir / "evidence"))
    record = ledger.append(
        f"article-14-{args.stage}",
        written,
        meta={
            "cve": args.cve,
            "product": product.name,
            "product_version": product.version,
            "aware_at": args.aware_at,
            "track": track.value,
            "triage_status": result.status.value,
            "tool_version": __version__,
            "spec_version": dossier.spec_version,
            "validated": not args.no_validate,
        },
    )

    for path in written:
        print(f"wrote {path}")
    print(f"evidence record {record.seq} at {record.recorded_at} (prev {record.prev[:12]}…)")
    print()

    if dossier.gaps:
        print(style.red(f"NOT READY — {len(dossier.gaps)} mandatory field(s) unanswered:"))
        for gap in dossier.gaps:
            print(f"  - {gap}")
        print(style.dim("  supply them with --field key=value, or --answers file.json"))
    else:
        print(style.green("every mandatory field for this stage has a value"))
    print()

    tl = timeline(args.aware_at, track=track, measure_available_at=args.measure_available)
    for ob in tl.obligations:
        left = ob.remaining()
        due = ob.due_at.isoformat() if ob.due_at else "not started"
        state = style.status(ob.urgency().value)
        text = f"  {ob.label:<38} {due}  [{state}]"
        if left is not None:
            remaining = ob.to_dict()["remaining"]
            # _fmt_delta already says "overdue"; appending "left" to it reads
            # as nonsense at exactly the moment someone is reading carefully.
            text += f"  {remaining}" if "overdue" in remaining else f"  {remaining} left"
        print(text)
    print()
    print(result.summary)
    if dossier.gaps:
        raise DossierIncomplete(
            "the dossier was written but is not submittable yet",
            dossier.gaps,
            hint="fill the fields above and re-run; the evidence ledger keeps both drafts",
        )
    return 0


def cmd_clock(args: argparse.Namespace) -> int:
    tl = timeline(args.aware_at, track=args.track, measure_available_at=args.measure_available)
    if args.json:
        print(json.dumps(tl.to_dict(), indent=2))
        return 0
    style = Style(_colour_enabled())
    print(f"aware at {tl.aware_at.isoformat()}  ({tl.track})")
    print()
    worst = tl.worst_urgency()
    for ob in tl.obligations:
        due = ob.due_at.isoformat() if ob.due_at else "not started"
        row = ob.to_dict()
        remaining = row["remaining"] or ""
        if remaining and "overdue" not in remaining:
            remaining += " left"
        print(
            f"  {ob.label:<38} {due}  [{style.status(row['urgency'])}]"
            + (f"  {remaining}" if remaining else "")
        )
        print(style.dim(f"    {ob.legal_basis} — {ob.basis}"))
    return 1 if worst.value == "overdue" else 0


def cmd_verify(args: argparse.Namespace) -> int:
    ledger = Ledger(args.evidence)
    ok, messages = ledger.verify(
        check_files=not args.chain_only, expect_head=args.expect_head or ""
    )
    style = Style(_colour_enabled())
    for message in messages:
        print(("  " if ok else style.red("  ")) + message)
    if ok and args.summary:
        print()
        print(json.dumps(ledger.summary(), indent=2))
    return 0 if ok else 1


def cmd_spec(args: argparse.Namespace) -> int:
    spec = config_mod.srp_spec()
    if args.json:
        print(json.dumps(spec, indent=2))
        return 0
    style = Style(_colour_enabled())
    print(style.bold(f"{spec['spec_name']} — version {spec['spec_version']}"))
    print(style.dim(spec["disclaimer"]))
    print()
    for stage in spec["stages"]:
        if args.stage and stage["id"] != args.stage:
            continue
        print(style.bold(f"{stage['label']} ({stage['id']})"))
        print(f"  {stage['legal_basis']}")
        print(f"  deadline: {stage['deadline_basis']}")
        print()
        for fs in config_mod.stage_fields(stage["id"]):
            mark = {"required": "*", "conditional": "?", "derived": "=", "optional": " "}.get(
                fs["requirement"], " "
            )
            print(f"   {mark} {fs['key']:<28} {fs['label']}")
            if fs.get("help") and args.verbose:
                print(style.dim(f"       {fs['help']}"))
        print()
    print(style.dim("  * required   ? conditional   = derived by cra24   (blank) optional"))
    if not args.stage:
        print()
        print(style.bold("Platform notes"))
        for note in spec["platform_notes"]:
            print(f"  - {note}")
    return 0


def cmd_feeds(args: argparse.Namespace) -> int:
    style = Style(_colour_enabled())
    names = ALL_FEEDS
    if getattr(args, "only", None):
        names = tuple(n.strip() for n in args.only.split(",") if n.strip())
    feeds = FeedSet(names, cache=Cache(args.cache_dir), offline=getattr(args, "offline", False))

    statuses = feeds.sync(force=args.force) if args.feeds_action == "sync" else feeds.status()

    if args.json:
        print(json.dumps([s.to_dict() for s in statuses], indent=2))
        return 0

    print(style.bold(f"cache: {feeds.cache.root}"))
    print()
    for status in statuses:
        mark = style.green("ok") if status.present else style.yellow("--")
        age = f"{status.age_hours}h ago" if status.age_hours is not None else "never"
        records = f"{status.records} records" if status.records is not None else ""
        print(f"  [{mark}] {status.name:<6} {age:<14} {records}")
        print(style.dim(f"        {status.host} — {status.note}"))
    print()
    if args.terms:
        print(style.bold("terms of use"))
        for name in names:
            feed = feeds.get(name)
            if feed is not None and feed.terms:
                print(f"  {name}: {feed.terms}")
        print()
    missing = [s.name for s in statuses if not s.present]
    if missing and args.feeds_action == "status":
        print(style.dim("  not cached: " + ", ".join(missing) + " — run `cra24 feeds sync`"))
    return 0


def cmd_watch(args: argparse.Namespace) -> int:
    from . import notify as notify_mod
    from . import watch as watch_mod

    style = Style(_colour_enabled())
    feeds = FeedSet(
        tuple(n.strip() for n in args.only.split(",") if n.strip()) if args.only else ALL_FEEDS,
        cache=Cache(args.cache_dir),
        offline=args.offline,
    )
    # --json means the output is being parsed, and the alerts are already in it.
    # Printing the default stdout notifier after the JSON would make the stream
    # unparseable, which is the kind of bug that only shows up in someone's
    # pipeline rather than in a terminal.
    default_notify = [] if args.json else ["stdout"]
    notifiers = [notify_mod.build(spec) for spec in (args.notify or default_notify)]

    def one_pass() -> int:
        if not args.offline and not args.no_sync:
            feeds.sync()
        result = watch_mod.run_once(
            args.products,
            feeds=feeds,
            state_path=args.state,
            dossier_root=args.out or "watch-dossiers",
            include_all_cves=args.all_cves,
            write_dossiers=not args.no_dossiers,
        )
        if args.json:
            print(json.dumps(result.to_dict(), indent=2))
        else:
            print(
                f"{result.checked_products} product(s), "
                f"{result.checked_cves} CVE(s) checked, "
                f"{len(result.alerts)} new alert(s), "
                f"{result.skipped_unchanged} unchanged"
            )
        for alert in result.alerts:
            notify_mod.send_all(notifiers, alert)
        for message in result.errors:
            print(style.yellow(f"  error: {message}"), file=sys.stderr)
        return 1 if any(a.reportable for a in result.alerts) else 0

    if args.once:
        return one_pass()

    import time

    print(style.dim(f"watching every {args.interval}s — Ctrl-C to stop"))
    while True:
        try:
            one_pass()
        except Cra24Error as exc:
            print(f"cra24: {exc}", file=sys.stderr)
        time.sleep(max(60, args.interval))


def cmd_doctor(args: argparse.Namespace) -> int:  # noqa: ARG001
    style = Style(_colour_enabled())
    spec = config_mod.srp_spec()
    print(style.bold(f"cra24 {__version__}"))
    print(f"  python           {sys.version.split()[0]}")
    print(f"  srp field spec   {spec['spec_version']}")
    print(f"  annex data       {config_mod.annex_spec()['spec_version']}")
    reason = validate_mod.unavailable_reason()
    print(
        f"  validation       {style.green('available') if not reason else style.red(reason)}"
        + ("" if not reason else "  (pip install 'cra24[validate]')")
    )
    key = evidence_mod.key_info()
    if not key["set"]:
        print("  evidence hmac    not set")
    else:
        detail = f"configured ({key['bytes']} bytes, read as {key['decoded_as']})"
        print(f"  evidence hmac    {style.red(detail) if key['weak'] else detail}")
        if key["weak"]:
            print(
                style.dim(
                    f"    a {key['bytes']}-byte key is not what stops someone forging a "
                    "record; a hex value is decoded as hex, so a passphrase of hex "
                    "characters yields half the bytes you typed"
                )
            )
    print()
    print(style.bold("feeds"))
    try:
        for status in FeedSet(cache=Cache(), offline=True).status():
            mark = style.green("cached") if status.present else style.dim("not cached")
            print(f"  {status.name:<6} {mark:<22} {status.host}")
    except Cra24Error as exc:  # pragma: no cover - defensive
        print(style.dim(f"  unavailable: {exc}"))
    print()
    print(style.bold("bundled schemas"))
    for entry in validate_mod.schema_inventory():
        print(f"  {entry['file']:<28} {entry['title'][:52]}")
        if entry["note"]:
            print(style.dim(f"    {entry['note'][:100]}"))
    print()
    print(style.dim(DISCLAIMER))
    return 0 if not reason else 1


# --------------------------------------------------------------------------
# parser
# --------------------------------------------------------------------------


def _common() -> argparse.ArgumentParser:
    """Flags accepted both before and after the subcommand.

    ``SUPPRESS`` defaults matter here: without them the subparser would overwrite
    a value the main parser already read, so ``cra24 -v check`` would silently
    lose its verbosity.
    """
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=argparse.SUPPRESS,
        help="repeat for more detail",
    )
    common.add_argument(
        "--json-logs",
        action="store_true",
        default=argparse.SUPPRESS,
        help="structured logs on stderr, for unattended runs",
    )
    return common


def build_parser() -> argparse.ArgumentParser:
    common = _common()
    parser = argparse.ArgumentParser(
        prog="cra24",
        parents=[common],
        description="Turn an embedded Linux build tree into a CRA Article 14 "
        "dossier. Unofficial; not affiliated with ENISA.",
        epilog="Dual licensed: AGPL-3.0-only, or a commercial licence. See LICENSING.md.",
    )
    parser.add_argument("--version", action="version", version=f"cra24 {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True, metavar="COMMAND")

    p = sub.add_parser("init", parents=[common], help="write a configuration template")
    p.add_argument("--out", metavar="FILE")
    p.add_argument("--name", default="MyProduct")
    p.add_argument("--product-version", default="1.0.0")
    p.add_argument("--force", action="store_true")
    p.set_defaults(func=cmd_init)

    p = sub.add_parser("scan", parents=[common], help="read a build into product.json")
    _source_args(p)
    p.add_argument(
        "--include-unshipped",
        action="store_true",
        help="keep recipes that were built but not installed in the image",
    )
    p.add_argument("--out", metavar="FILE")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser(
        "check", parents=[common], help="is this CVE actually in the shipped image?"
    )
    _source_args(p)
    _feed_args(p)
    p.add_argument("cve")
    p.add_argument(
        "--actively-exploited",
        choices=["yes", "no", "unknown"],
        help="evidence of active exploitation; Article 14(1) turns on this",
    )
    p.add_argument("--fixed-version", help="version the advisory says fixes it")
    p.add_argument(
        "--gate",
        action="append",
        metavar="CONFIG_SYM[,...]",
        help="kernel config symbols gating this CVE's code; repeatable. "
        "A symbol that is unset in the shipped .config downgrades "
        "affected to not_affected.",
    )
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_check)

    p = sub.add_parser(
        "report", parents=[common], help="emit the dossier, advisory, VEX and evidence"
    )
    _source_args(p)
    _feed_args(p)
    p.add_argument("cve")
    p.add_argument(
        "--aware-at",
        required=True,
        metavar="ISO8601",
        help="the moment you became aware, e.g. 2026-09-17T08:30:00Z",
    )
    p.add_argument("--stage", choices=STAGES, default="early_warning")
    p.add_argument("--track", choices=["vulnerability", "incident"], default="vulnerability")
    p.add_argument("--actively-exploited", choices=["yes", "no", "unknown"])
    p.add_argument("--severity", choices=["low", "medium", "high", "critical", "unknown"])
    p.add_argument("--malicious-intent", choices=["yes", "no", "unknown"])
    p.add_argument("--cross-border", choices=["yes", "no", "unknown"])
    p.add_argument("--summary", help="the few sentences a duty officer can act on")
    p.add_argument(
        "--field",
        action="append",
        metavar="KEY=VALUE",
        help="answer any SRP field directly; repeatable",
    )
    p.add_argument("--answers", metavar="FILE", help="JSON or TOML file of field answers")
    p.add_argument("--fixed-version")
    p.add_argument(
        "--gate",
        action="append",
        metavar="CONFIG_SYM[,...]",
        help="kernel config symbols gating this CVE's code; repeatable",
    )
    p.add_argument(
        "--measure-available",
        metavar="ISO8601",
        help="when the corrective measure shipped; starts the 14-day clock",
    )
    p.add_argument("--tracking-id", help="CSAF advisory id (derived when omitted)")
    p.add_argument("--vex-id", help="OpenVEX document @id (derived when omitted)")
    p.add_argument(
        "--doc-version",
        type=int,
        default=1,
        help="advisory and VEX version; increment when you republish",
    )
    p.add_argument("--tlp", default="WHITE", choices=["RED", "AMBER", "GREEN", "WHITE"])
    p.add_argument(
        "--no-validate",
        action="store_true",
        help="skip schema validation of the emitted documents",
    )
    p.add_argument("--evidence", metavar="DIR")
    p.add_argument("--out", metavar="DIR")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("clock", parents=[common], help="just the deadlines")
    p.add_argument("--aware-at", required=True, metavar="ISO8601")
    p.add_argument("--track", choices=["vulnerability", "incident"], default="vulnerability")
    p.add_argument("--measure-available", metavar="ISO8601")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_clock)

    p = sub.add_parser("verify", parents=[common], help="check the evidence hash chain")
    p.add_argument("evidence", metavar="DIR")
    p.add_argument(
        "--chain-only",
        action="store_true",
        help="verify the chain without re-hashing the artefacts",
    )
    p.add_argument(
        "--expect-head",
        metavar="SHA256",
        default="",
        help="require the chain to end at this head hash, as anchored elsewhere; "
        "truncation leaves a shorter chain that is otherwise still intact",
    )
    p.add_argument("--summary", action="store_true")
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser(
        "spec", parents=[common], help="show the SRP field spec this release carries"
    )
    p.add_argument("--stage", choices=STAGES)
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_spec)

    p = sub.add_parser(
        "feeds",
        parents=[common],
        help="sync or inspect the vulnerability feeds",
        description="cra24 makes no network call you did not ask for. This is "
        "where you ask for one.",
    )
    p.add_argument(
        "feeds_action",
        choices=["sync", "status"],
        metavar="ACTION",
        help="sync (fetch if stale) or status (what is cached)",
    )
    p.add_argument(
        "--only", metavar="LIST", help=f"comma-separated subset of {', '.join(ALL_FEEDS)}"
    )
    p.add_argument("--force", action="store_true", help="re-fetch even if the cache is fresh")
    p.add_argument(
        "--offline", action="store_true", help="do not open a socket; report what is cached"
    )
    p.add_argument("--cache-dir", metavar="DIR")
    p.add_argument("--terms", action="store_true", help="also print each feed's terms of use")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_feeds)

    p = sub.add_parser(
        "watch",
        parents=[common],
        help="poll the feeds against registered products and fire when something lands",
        description="Writes the dossier and starts the clock at the moment of "
        "detection, so what reaches you is a draft rather than an alert.",
    )
    p.add_argument(
        "--products",
        required=True,
        metavar="PATH",
        help="a product.json, or a directory of them (one per device family)",
    )
    p.add_argument(
        "--once", action="store_true", help="one pass and exit, for cron or a CI job"
    )
    p.add_argument(
        "--interval",
        type=int,
        default=3600,
        metavar="SECONDS",
        help="seconds between passes when looping (minimum 60, default 3600)",
    )
    p.add_argument(
        "--notify",
        action="append",
        metavar="SPEC",
        help="stdout, file:PATH, webhook:URL or email:ADDRESS; repeatable",
    )
    p.add_argument(
        "--state",
        metavar="FILE",
        help="where to keep watch state (default alongside --products)",
    )
    p.add_argument(
        "--out", metavar="DIR", help="where to write dossiers (default watch-dossiers)"
    )
    p.add_argument("--only", metavar="LIST", help="restrict to these feeds")
    p.add_argument(
        "--all-cves",
        action="store_true",
        help="also check CVEs the build reports as patched or ignored",
    )
    p.add_argument("--no-dossiers", action="store_true", help="alert without writing dossiers")
    p.add_argument(
        "--no-sync", action="store_true", help="do not refresh the feeds before each pass"
    )
    p.add_argument("--offline", action="store_true")
    p.add_argument("--cache-dir", metavar="DIR")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_watch)

    p = sub.add_parser(
        "doctor", parents=[common], help="what this installation knows and can do"
    )
    p.set_defaults(func=cmd_doctor)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    verbose = getattr(args, "verbose", 0)
    args.verbose = verbose
    log_mod.configure(verbose, json_logs=getattr(args, "json_logs", False) or None)
    try:
        return int(args.func(args))
    except DossierIncomplete as exc:
        print(f"\n{exc}", file=sys.stderr)
        return exc.exit_code
    except Cra24Error as exc:
        print(f"cra24: {exc}", file=sys.stderr)
        return exc.exit_code
    except KeyboardInterrupt:  # pragma: no cover
        print("interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
