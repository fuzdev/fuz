// HTTPS test server for scripts/install-test.sh, run by Node as TypeScript
// (`node scripts/install-test/serve.ts`; erasable syntax only, no dependencies).
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
//                                  second listener below (see the TLS note)
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
//   /wredirect     301 to the plain-HTTP listener's valid `/wok/latest/...`
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
// The same routes are served by two listeners: the HTTPS one the harness points
// install.sh at, and a plain-HTTP one whose only job is to be a valid downgrade
// target. `redirect` sends install.sh at that HTTP `/ok/...` — bytes and digest
// are entirely correct there, so the *only* thing that can fail the install is
// curl's `--proto '=https'` refusing to follow https→http. Removing that flag
// from install.sh turns the case green, which is what makes the case a pin.
//
// The HTTPS listener offers HTTP/2 and HTTP/1.1 by ALPN, as a real release host
// does: curl negotiates h2, and wget, which speaks only HTTP/1.1, gets that.
//
// A third listener, `SILENT_PORT`, accepts TCP connections and never says
// anything: an origin install.sh is still waiting on when the harness signals
// it. It is a bare socket rather than a slow scenario because the client is
// killed mid-request, and it has no request to abandon.
//
// Target-agnostic: the release host matches any `/fuz-*` name and a release log
// scenario echoes the target it was asked for, so the harness needn't know the
// host's target triple. Env: PORT, CERT, KEY (PEM paths), STUB_PATH.

import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { createServer as create_http_server } from "node:http";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createSecureServer } from "node:http2";
import type { Http2ServerRequest, Http2ServerResponse } from "node:http2";
import { createServer as create_tcp_server } from "node:net";
import type { Server } from "node:net";
import process from "node:process";

// What a route answers. A body is sent with its `content-length`, as a host
// serving files sends it; a reply without one (a redirect, a 304) has none.
interface Reply {
	status: number;
	headers?: Record<string, string>;
	body?: Uint8Array;
}

const env_path = (name: string): string => {
	const value = process.env[name];
	if (!value) throw new Error(`serve.ts: ${name} must name a file`);
	return value;
};

const cert = readFileSync(env_path("CERT"), "utf8");
const key = readFileSync(env_path("KEY"), "utf8");
const stub = readFileSync(env_path("STUB_PATH"));

const hex = createHash("sha512").update(stub).digest("hex");

// The version every release log pointer names. Nothing depends on its value:
// the release host serves the stub under any `fuz-*` name.
const VERSION = "0.9.9";

// Per-path hit counter, used only by the `flaky` and `wflaky` scenarios.
const hits = new Map<string, number>();

// Port of the plain-HTTP listener, which is listening before the HTTPS one
// starts (see the bottom of this file): the `redirect` scenarios' Location
// embeds it.
let http_port = 0;

const encoder = new TextEncoder();
const reply = (body: string | Uint8Array, status = 200): Reply => ({
	status,
	body: typeof body === "string" ? encoder.encode(body) : body,
});
const not_found = (): Reply => reply("nope", 404);
const redirect_to_http = (path: string): Reply => ({
	status: 301,
	headers: { location: `http://localhost:${http_port}${path}` },
});

// A release log origin's answer for `scenario`, or `undefined` when `scenario`
// is not a release log scenario.
function pointer(scenario: string, leaf: string): Reply | undefined {
	if (!scenario.startsWith("w")) return undefined;
	// Unanchored at the start: an origin may sit under a base path.
	const target = /\/latest\/fuz-([^/]+)\.sha512$/.exec(leaf)?.[1];
	if (target === undefined || leaf.includes("//")) return not_found();
	const name = `fuz-${VERSION}-${target}`;
	const line = (file: string, sum = hex): string => `${sum}  ${file}\n`;
	switch (scenario) {
		case "wok":
			return reply(line(name));
		case "wmismatch":
			return reply(line(name, "0".repeat(128)));
		case "wabsent":
			return not_found();
		case "wgone":
			return reply("gone", 410);
		case "w403":
			return reply("forbidden", 403);
		case "w503":
			return reply("later", 503);
		case "wflaky": {
			const n = hits.get(leaf) ?? 0;
			hits.set(leaf, n + 1);
			if (n < 2) return reply("later", 503);
			return reply(line(name));
		}
		case "wredirect":
			return redirect_to_http(`/wok${leaf}`);
		case "w304":
			return { status: 304 };
		case "wupper":
			return reply(line(name, hex.toUpperCase()));
		case "wsha256len":
			return reply(line(name, hex.slice(0, 64)));
		case "wempty":
			return reply("");
		case "wnonl":
			return reply(line(name).trimEnd());
		case "wcrlf":
			return reply(`${hex}  ${name}\r\n`);
		case "wmultiline":
			return reply(line(name) + line(name));
		case "wpartial":
			return reply(`${line(name)}x`);
		case "wextra":
			return reply(`${hex}  ${name} extra\n`);
		case "wonespace":
			return reply(`${hex} ${name}\n`);
		case "wtab":
			return reply(`${hex}\t${name}\n`);
		case "wthreespace":
			return reply(`${hex}   ${name}\n`);
		case "wlead":
			return reply(` ${line(name)}`);
		case "wbig":
			return reply(line(`fuz-${"1".repeat(2000)}-${target}`));
		case "wbadname":
			return reply(line(`fuz-${VERSION}/x-${target}`));
		case "wbadchar":
			return reply(line(`fuz-${VERSION};x-${target}`));
		case "wplus":
			return reply(line(`fuz-${VERSION}+b1-${target}`));
		case "wdotdot":
			return reply(line(`fuz-0..9-${target}`));
		case "wnoversion":
			return reply(line(`fuz--${target}`));
		case "wlatest":
			return reply(line(`fuz-latest-${target}`));
		case "wothertarget":
			return reply(line(`fuz-${VERSION}-other-target`));
		case "wnotfuz":
			return reply(line(`notfuz-${VERSION}-${target}`));
		default:
			return undefined;
	}
}

// The answer for a request's path, either listener.
function route(pathname: string): Reply {
	const slash = pathname.indexOf("/", 1);
	const scenario = pathname.slice(1, slash === -1 ? undefined : slash);
	const leaf = slash === -1 ? "" : pathname.slice(slash);

	if (scenario === "notfound") return not_found();

	const pointed = pointer(scenario, leaf);
	if (pointed !== undefined) return pointed;

	if (scenario === "flaky") {
		const n = hits.get(pathname) ?? 0;
		hits.set(pathname, n + 1);
		if (n < 2) return reply("later", 503);
	}

	if (!leaf.startsWith("/fuz-")) return not_found();

	// Both the binary and its sidecar redirect — a downgrade that only moved
	// the sidecar would fail for the wrong reason (a missing binary).
	if (scenario === "redirect") return redirect_to_http(`/ok${leaf}`);

	// Nothing an install without a release log reads: no moving `fuz-latest-*`
	// name, no sidecar.
	if (scenario === "vonly" && (leaf.startsWith("/fuz-latest-") || leaf.endsWith(".sha512"))) {
		return not_found();
	}

	if (!leaf.endsWith(".sha512")) return reply(stub);

	// Serves the binary but not its sidecar — install.sh must report the
	// sidecar as missing, not claim the target is unsupported.
	if (scenario === "nosidecar") return not_found();

	// sha512 sidecar: "<hash>  <filename>\n" — install.sh reads field 1 only.
	// The 128 zeros must match install.sh's expected hex length, or this case
	// trips the malformed-digest guard instead of the mismatch it's testing.
	if (scenario === "badsum") return reply(`${"0".repeat(128)}  fuz\n`);
	if (scenario === "malformed") return reply("not-a-valid-digest  fuz\n");
	// A digest field built to drive the terminal that prints the refusal: an
	// erase-line sequence, a carriage return, a direction override.
	if (scenario === "hostile") return reply("x\x1b[2K\r\u202ey  fuz\n");
	// A digest field far longer than a digest: the refusal shows a bounded part.
	if (scenario === "longfield") return reply(`${"z".repeat(600)}  fuz\n`);
	if (scenario === "upper") return reply(`${hex.toUpperCase()}  fuz\n`);
	// Well-formed lowercase hex of the *wrong length* — a sha256 digest where a
	// sha512 one belongs. Charset validation alone accepts it, so this reaches
	// install.sh's 128-length guard and nothing else.
	if (scenario === "sha256len") return reply(`${hex.slice(0, 64)}  fuz\n`);
	return reply(`${hex}  fuz\n`);
}

function serve(
	req: IncomingMessage | Http2ServerRequest,
	res: ServerResponse | Http2ServerResponse,
): void {
	// Prefixed with an origin rather than resolved against a base, which
	// would read a leading `//` as a host: the path keeps every empty segment.
	const { pathname } = new URL(`http://localhost${req.url}`);
	// One line per request on stdout (the harness's `server.out`), so a case
	// can assert that install.sh requested nothing under its scenario.
	console.log(`REQ ${pathname}`);
	const { status, headers, body } = route(pathname);
	res.writeHead(
		status,
		body === undefined ? headers : { ...headers, "content-length": String(body.byteLength) },
	);
	res.end(body);
}

// Listens on `port` (0: the OS picks a free one) and resolves to the port. A
// failure to listen rejects; an error after that is unhandled, and ends the
// server, which the harness reports.
const listen = (server: Server, port: number): Promise<number> =>
	new Promise((resolve, reject) => {
		server.once("error", reject);
		server.listen(port, "localhost", () => {
			server.off("error", reject);
			const address = server.address();
			if (address === null || typeof address === "string") {
				reject(new Error("serve.ts: listener has no port"));
				return;
			}
			resolve(address.port);
		});
	});

// The plain-HTTP listener comes up first, so `http_port` is known before the
// HTTPS listener can accept a request. The harness greps an anchored `^PORT=`
// and waits for it, so `PORT=` is printed last; the other lines are read once it
// appears, and are also for reproducing a case by hand.
http_port = await listen(create_http_server(serve), 0);
console.log(`HTTP_PORT=${http_port}`);

// Accepted sockets are held open and never read or written.
const silent_port = await listen(create_tcp_server(), 0);
console.log(`SILENT_PORT=${silent_port}`);

const port = await listen(
	createSecureServer({ cert, key, allowHTTP1: true }, serve),
	Number(process.env.PORT ?? "0"),
);
console.log(`PORT=${port}`);
