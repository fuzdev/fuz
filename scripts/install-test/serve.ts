// HTTPS test server for scripts/install-test.sh.
//
// Serves a stub "fuz binary", its sha512 sidecar, and release log pointers over
// TLS so the real install.sh (which forces `--proto '=https' --tlsv1.2`) can be
// exercised end-to-end against localhost. The first path segment selects a
// scenario. One server plays both roles install.sh talks to — the release host
// (`FUZ_INSTALL_BASE_URL`) and a release log origin (`FUZ_RELEASE_LOG_URL`) —
// so a case picks one scenario of each kind.
//
// Release host scenarios:
//
//   /ok/fuz-<name>[.sha512]        correct binary + matching digest
//   /notfound/...                  404
//   /nosidecar/...                 binary 200, sidecar 404 (a host serving an
//                                  older layout, e.g. still .sha256-only)
//   /badsum/...sha512              valid-shape digest that won't match
//   /malformed/...sha512           non-hex garbage digest
//   /hostile/...sha512             a digest field holding an escape sequence,
//                                  a carriage return, and a direction override
//   /longfield/...sha512           a digest field of 600 characters
//   /upper/...sha512               correct digest in UPPERCASE hex (hex case
//                                  carries no meaning; must verify, not "tamper")
//   /sha256len/...sha512           valid lowercase hex, but 64 chars (sha256
//                                  length) — only the 128-length guard rejects it
//   /flaky/...                     503 for the first 2 hits per path, then 200
//                                  (exercises curl's --retry)
//   /redirect/...                  301 to the *plain-HTTP* `/ok/...` of the
//                                  second server below (see the TLS note)
//   /vonly/...                     versioned binaries only: every `fuz-latest-*`
//                                  and every `.sha512` is 404 — a host that can
//                                  only satisfy an install that reads neither
//   /musl/...                      the same as `ok` (any name not listed here
//                                  is): a scenario only the musl case uses, so
//                                  its `REQ /musl/` lines are its own
//   /relhome/...                   the same as `ok`, for the relative-HOME
//                                  case alone (its `REQ` lines are its own)
//
// Release log scenarios answer `/<scenario>[/<base path>]/latest/fuz-<target>.sha512`
// and 404 everything else. `<v>` is the fixed VERSION below, `<t>` the requested target:
//
//   /wok           `<digest>  fuz-<v>-<t>\n` — the correct pointer
//   /wmismatch     well-formed pointer whose digest is not the binary's
//   /wabsent       404
//   /wgone         410
//   /w403          403 (an origin that does not serve the file: unreachable)
//   /w503          503, always (unreachable after the retries)
//   /wflaky        503 for the first 2 hits, then the correct pointer
//   /wredirect     301 to the plain-HTTP server's valid `/wok/latest/...`
//   /w304          304 with no body (curl succeeds and writes no file)
//   /wupper        correct digest in UPPERCASE hex (must verify)
//   /wsha256len    64-hex digest
//   /wempty        empty body
//   /wnonl         the correct line without its trailing newline
//   /wcrlf         the correct line ending in CRLF
//   /wmultiline    two lines, each one correct
//   /wpartial      the correct line, then an unterminated fragment
//   /wextra        a third field after the name
//   /wonespace     one space between digest and name
//   /wtab          a tab between digest and name
//   /wthreespace   three spaces between digest and name
//   /wlead         a space before the digest
//   /wbig          a well-formed line longer than a pointer may be
//   /wbadname      a `/` in the name
//   /wbadchar      a character outside the name charset (`;`)
//   /wplus         a `+` in the name (a version with build metadata)
//   /wdotdot       `..` in the name
//   /wnoversion    `fuz--<t>` — no version
//   /wlatest       `fuz-latest-<t>` — the moving name, not a version
//   /wothertarget  a name for a different target
//   /wnotfuz       a name that is not a `fuz-` binary
//
// A path with an empty segment (`//`) is a 404, so an origin given with a
// trailing slash is only served if install.sh strips it.
//
// Each malformed pointer is otherwise valid — the right digest, a name the
// release host would serve — so the guard it is aimed at is the only thing
// between it and a successful install.
//
// The same handler is mounted on two servers: the HTTPS one the harness points
// install.sh at, and a plain-HTTP one whose only job is to be a valid downgrade
// target. `redirect` sends install.sh at that HTTP `/ok/...` — bytes and digest
// are entirely correct there, so the *only* thing that can fail the install is
// curl's `--proto '=https'` refusing to follow https→http. Removing that flag
// from install.sh turns the case green, which is what makes the case a pin.
//
// A third listener, `SILENT_PORT`, accepts TCP connections and never says
// anything: an origin install.sh is still waiting on when the harness signals
// it. It is a bare socket rather than a slow scenario because the client is
// killed mid-request, and it has no request to abandon.
//
// Target-agnostic: the release host matches any `/fuz-*` name and a release log
// scenario echoes the target it was asked for, so the harness needn't know the
// host's target triple. Env: PORT, CERT, KEY (PEM paths), STUB_PATH.

const cert = Deno.readTextFileSync(Deno.env.get("CERT")!);
const key = Deno.readTextFileSync(Deno.env.get("KEY")!);
const stub = Deno.readFileSync(Deno.env.get("STUB_PATH")!);

const digest = await crypto.subtle.digest("SHA-512", stub);
const hex = Array.from(new Uint8Array(digest))
	.map((b) => b.toString(16).padStart(2, "0"))
	.join("");

// The version every release log pointer names. Nothing depends on its value:
// the release host serves the stub under any `fuz-*` name.
const VERSION = "0.9.9";

// Per-path hit counter, used only by the `flaky` and `wflaky` scenarios.
const hits = new Map<string, number>();

// Port of the plain-HTTP server; assigned before the HTTPS server is
// constructed (the top-level await below gates HTTPS construction on this
// value, which the `redirect` scenario's Location embeds).
let http_port = 0;

const not_found = (): Response => new Response("nope", { status: 404 });

// A release log origin's answer for `scenario`, or `undefined` when `scenario`
// is not a release log scenario.
function pointer(scenario: string, leaf: string): Response | undefined {
	if (!scenario.startsWith("w")) return undefined;
	// Unanchored at the start: an origin may sit under a base path.
	const target = /\/latest\/fuz-([^/]+)\.sha512$/.exec(leaf)?.[1];
	if (target === undefined || leaf.includes("//")) return not_found();
	const name = `fuz-${VERSION}-${target}`;
	const line = (file: string, sum = hex): string => `${sum}  ${file}\n`;
	switch (scenario) {
		case "wok":
			return new Response(line(name));
		case "wmismatch":
			return new Response(line(name, "0".repeat(128)));
		case "wabsent":
			return not_found();
		case "wgone":
			return new Response("gone", { status: 410 });
		case "w403":
			return new Response("forbidden", { status: 403 });
		case "w503":
			return new Response("later", { status: 503 });
		case "wflaky": {
			const n = hits.get(leaf) ?? 0;
			hits.set(leaf, n + 1);
			if (n < 2) return new Response("later", { status: 503 });
			return new Response(line(name));
		}
		case "wredirect":
			return new Response(null, {
				status: 301,
				headers: { location: `http://localhost:${http_port}/wok${leaf}` },
			});
		case "w304":
			return new Response(null, { status: 304 });
		case "wupper":
			return new Response(line(name, hex.toUpperCase()));
		case "wsha256len":
			return new Response(line(name, hex.slice(0, 64)));
		case "wempty":
			return new Response("");
		case "wnonl":
			return new Response(line(name).trimEnd());
		case "wcrlf":
			return new Response(`${hex}  ${name}\r\n`);
		case "wmultiline":
			return new Response(line(name) + line(name));
		case "wpartial":
			return new Response(`${line(name)}x`);
		case "wextra":
			return new Response(`${hex}  ${name} extra\n`);
		case "wonespace":
			return new Response(`${hex} ${name}\n`);
		case "wtab":
			return new Response(`${hex}\t${name}\n`);
		case "wthreespace":
			return new Response(`${hex}   ${name}\n`);
		case "wlead":
			return new Response(` ${line(name)}`);
		case "wbig":
			return new Response(line(`fuz-${"1".repeat(2000)}-${target}`));
		case "wbadname":
			return new Response(line(`fuz-${VERSION}/x-${target}`));
		case "wbadchar":
			return new Response(line(`fuz-${VERSION};x-${target}`));
		case "wplus":
			return new Response(line(`fuz-${VERSION}+b1-${target}`));
		case "wdotdot":
			return new Response(line(`fuz-0..9-${target}`));
		case "wnoversion":
			return new Response(line(`fuz--${target}`));
		case "wlatest":
			return new Response(line(`fuz-latest-${target}`));
		case "wothertarget":
			return new Response(line(`fuz-${VERSION}-other-target`));
		case "wnotfuz":
			return new Response(line(`notfuz-${VERSION}-${target}`));
		default:
			return undefined;
	}
}

function handler(req: Request): Response {
	const { pathname } = new URL(req.url);
	// One line per request on stdout (the harness's `server.out`), so a case
	// can assert that install.sh requested nothing under its scenario.
	console.log(`REQ ${pathname}`);
	const slash = pathname.indexOf("/", 1);
	const scenario = pathname.slice(1, slash === -1 ? undefined : slash);
	const leaf = slash === -1 ? "" : pathname.slice(slash);

	if (scenario === "notfound") return not_found();

	const pointed = pointer(scenario, leaf);
	if (pointed !== undefined) return pointed;

	if (scenario === "flaky") {
		const n = hits.get(pathname) ?? 0;
		hits.set(pathname, n + 1);
		if (n < 2) return new Response("later", { status: 503 });
	}

	if (!leaf.startsWith("/fuz-")) return not_found();

	// Both the binary and its sidecar redirect — a downgrade that only moved
	// the sidecar would fail for the wrong reason (a missing binary).
	if (scenario === "redirect") {
		return new Response(null, {
			status: 301,
			headers: { location: `http://localhost:${http_port}/ok${leaf}` },
		});
	}

	// Nothing an install without a release log reads: no moving `fuz-latest-*`
	// name, no sidecar.
	if (
		scenario === "vonly" &&
		(leaf.startsWith("/fuz-latest-") || leaf.endsWith(".sha512"))
	) {
		return not_found();
	}

	if (!leaf.endsWith(".sha512")) {
		return new Response(stub, { status: 200 });
	}

	// Serves the binary but not its sidecar — install.sh must report the
	// sidecar as missing, not claim the target is unsupported.
	if (scenario === "nosidecar") return not_found();

	// sha512 sidecar: "<hash>  <filename>\n" — install.sh reads field 1 only.
	// The 128 zeros must match install.sh's expected hex length, or this case
	// trips the malformed-digest guard instead of the mismatch it's testing.
	if (scenario === "badsum") return new Response(`${"0".repeat(128)}  fuz\n`);
	if (scenario === "malformed") return new Response("not-a-valid-digest  fuz\n");
	// A digest field built to drive the terminal that prints the refusal: an
	// erase-line sequence, a carriage return, a direction override.
	if (scenario === "hostile") return new Response("x\x1b[2K\r\u202ey  fuz\n");
	// A digest field far longer than a digest: the refusal shows a bounded part.
	if (scenario === "longfield") return new Response(`${"z".repeat(600)}  fuz\n`);
	if (scenario === "upper") return new Response(`${hex.toUpperCase()}  fuz\n`);
	// Well-formed lowercase hex of the *wrong length* — a sha256 digest where a
	// sha512 one belongs. Charset validation alone accepts it, so this reaches
	// install.sh's 128-length guard and nothing else.
	if (scenario === "sha256len") return new Response(`${hex.slice(0, 64)}  fuz\n`);
	return new Response(`${hex}  fuz\n`);
}

// Port 0 → the OS picks a free port. The plain-HTTP server comes up first and
// is awaited, so `http_port` is known before the HTTPS server can accept a
// request (the `redirect` scenario's Location embeds it). The harness greps an
// anchored `^PORT=`, so the extra `HTTP_PORT=` line is inert there — it's for
// reproducing a case by hand.
http_port = await new Promise<number>((resolve) => {
	Deno.serve(
		{ port: 0, hostname: "localhost", onListen: (addr) => resolve(addr.port) },
		handler,
	);
});
console.log(`HTTP_PORT=${http_port}`);

const silent = Deno.listen({ port: 0, hostname: "localhost" });
console.log(`SILENT_PORT=${(silent.addr as Deno.NetAddr).port}`);
(async () => {
	const held: Deno.Conn[] = [];
	for await (const conn of silent) held.push(conn);
})();

Deno.serve(
	{
		port: Number(Deno.env.get("PORT") ?? "0"),
		hostname: "localhost",
		cert,
		key,
		onListen: (addr) => console.log(`PORT=${addr.port}`),
	},
	handler,
);
