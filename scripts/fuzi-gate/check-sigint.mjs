// The real-SIGINT check: interrupt a `fuzi install` while its staging tree is
// on disk, and assert the interrupt drain did its job — and owned the outcome.
//
// Run in a project that is already installed, with a warm cache: the install
// here is `--offline`, so the only slow phase is materialization, which is
// exactly where the staging tree lives. The child is spawned from node, not
// backgrounded by the shell — a non-interactive shell starts `&` jobs with
// SIGINT ignored, and fuzi honors an inherited ignore, so a shell-sent SIGINT
// would test nothing. libuv resets every signal to its default in the child.
//
// The child is duty-cycled so detection latency can't lose the race: SIGCONT,
// a short quantum, SIGSTOP, then wait until every thread of it is stopped (`T`
// in `/proc/<pid>/task/*/stat`). A staging tree seen while the child is frozen
// has not been swapped yet, and the SIGINT that goes out then (delivered by the
// following SIGCONT) arrives at most one quantum after the staging root
// appeared, with the rest of staging still ahead, however slow this checker or
// the box is. A drain that still loses to the publish reads as a retry, never a
// pass. Linux-only (`/proc`), as both gate legs are. Every exit path continues
// the child: a stopped fuzi must never outlive the check or hang the gate. A
// SIGKILL of this checker is the one exit it cannot cover: fuzi then stays
// stopped (it holds no lock, so the gate still proceeds and fails).
//
// An attempt passes only on evidence that the drain caught the tree: exit 130 (128 + SIGINT),
// no `.fuzi-installing-*` left, and the drain's own removal line on stderr. An
// install that finishes first, or a signal that arrives after the swap
// published the tree (exit 0, or exit 130 with no removal line — the drain had
// nothing to remove), lost the race and is retried; one never caught
// mid-staging in every attempt fails the check (it proved nothing).
//
// Two modes, each needing `PASSES` passes (one can be luck). Human: no `error:` line — after a
// drain fires, the install thread renders nothing. `--json`: stdout is empty or
// one complete document, never a cut one — and a document that parses must not
// claim an exit code the process did not exit with.
//
// Usage: node check-sigint.mjs <path-to-fuzi>

import {spawn} from 'node:child_process';
import {readdirSync, readFileSync} from 'node:fs';

const fuzi = process.argv[2];
const ATTEMPTS = 12;
const PASSES = 3; // a lost-race-prone regression passes one attempt often; three in a row rarely
// The drain's report line (`report_drain` in `crates/fuzi/src/signal.rs`).
const REMOVED_LINE = 'fuzi: interrupted — removed 1 staging tree(s)';
const QUANTUM_MS = 1; // how long the child runs between freezes
const FREEZE_POLL_MS = 0.05; // between `/proc` reads while waiting for every thread to stop
const FREEZE_TIMEOUT_MS = 5_000; // a thread not stopped by then fails the attempt
const CYCLE_DEADLINE_MS = 120_000; // stop duty-cycling (and let the install run) after this

// A synchronous sleep, sub-millisecond capable: the child runs (or settles into
// its stop) while this process does nothing at all.
const sleep_sync_buffer = new Int32Array(new SharedArrayBuffer(4));
const sleep_sync = (ms) => Atomics.wait(sleep_sync_buffer, 0, 0, ms);

// The child currently spawned, so every exit path of this process can continue it.
let live_child = null;
const continue_live_child = () => {
	if (live_child === null) return;
	try {
		process.kill(live_child.pid, 'SIGCONT');
	} catch {
		// already gone
	}
};
process.on('exit', continue_live_child);
for (const [name, number] of [
	['SIGINT', 2],
	['SIGTERM', 15],
	['SIGHUP', 1],
]) {
	process.on(name, () => {
		continue_live_child();
		process.exit(128 + number);
	});
}

/** A task's state letter: the first field after the last `)` of its `stat`. */
const task_state = (path) => {
	let stat;
	try {
		stat = readFileSync(path, 'latin1');
	} catch {
		return null; // the task exited
	}
	return stat.slice(stat.lastIndexOf(')') + 1).trim()[0] ?? null;
};

/**
 * Wait until no thread of `pid` is running — each stopped (`T`), a zombie, or
 * gone. Returns `'frozen'`, or `'exited'` when the process itself has ended (its
 * leader a zombie or reaped). Throws after `FREEZE_TIMEOUT_MS`.
 */
const wait_frozen = (pid) => {
	const deadline = Date.now() + FREEZE_TIMEOUT_MS;
	for (;;) {
		const leader = task_state(`/proc/${pid}/stat`);
		if (leader === null || leader === 'Z' || leader === 'X') return 'exited';
		let tids;
		try {
			tids = readdirSync(`/proc/${pid}/task`);
		} catch {
			return 'exited';
		}
		const running = tids.filter((tid) => {
			const state = task_state(`/proc/${pid}/task/${tid}/stat`);
			return state !== null && state !== 'T' && state !== 'Z' && state !== 'X';
		});
		if (running.length === 0) return 'frozen';
		if (Date.now() > deadline) {
			throw Error(`fuzi thread(s) ${running.join(', ')} not stopped after ${FREEZE_TIMEOUT_MS} ms`);
		}
		sleep_sync(FREEZE_POLL_MS);
	}
};

/**
 * Duty-cycle `child` until a staging tree is seen while it is frozen (then
 * SIGINT it), it exits, or `CYCLE_DEADLINE_MS` passes. Returns the cycle count
 * at the catch, or `null` when nothing was caught. The child is left running.
 */
const catch_mid_staging = async (child, has_exited) => {
	const deadline = Date.now() + CYCLE_DEADLINE_MS;
	let cycles = 0;
	while (!has_exited() && Date.now() < deadline) {
		cycles++;
		child.kill('SIGCONT');
		sleep_sync(QUANTUM_MS);
		child.kill('SIGSTOP');
		if (wait_frozen(child.pid) === 'exited') return null;
		if (staging().length > 0) {
			// queued while stopped, delivered by the SIGCONT
			child.kill('SIGINT');
			child.kill('SIGCONT');
			return cycles;
		}
		// let node see an exit and drain the pipes while the child stays frozen
		await new Promise((resolve) => setImmediate(resolve));
	}
	child.kill('SIGCONT');
	return null;
};

const staging = () => readdirSync('.').filter((name) => name.startsWith('.fuzi-installing-'));

if (staging().length > 0) {
	console.error(`staging tree(s) present before the check: ${staging().join(', ')}`);
	process.exit(1);
}

/** One interrupted install: `{caught, code, signal, left, stdout, stderr}`. */
const interrupt_once = async (json) => {
	const args = ['install', '--offline', '--quiet'];
	if (json) args.push('--json');
	const child = spawn(fuzi, args, {stdio: ['ignore', 'pipe', 'pipe']});
	let stdout = '';
	let stderr = '';
	child.stdout.on('data', (chunk) => {
		stdout += chunk;
	});
	child.stderr.on('data', (chunk) => {
		stderr += chunk;
	});
	let exited = false;
	// `close`, not `exit`: the streams are drained by then, so a cut document is
	// fuzi's, not this reader's.
	const closed = new Promise((resolve) => {
		child.on('close', (code, signal) => resolve({code, signal}));
	});
	child.on('exit', () => {
		exited = true;
	});
	live_child = child;
	let cycles = null;
	let error = null;
	try {
		cycles = await catch_mid_staging(child, () => exited);
	} catch (err) {
		error = err;
	} finally {
		// whatever happened above, the child runs to its end
		if (!exited) child.kill('SIGCONT');
	}
	const {code, signal} = await closed;
	live_child = null;
	return {caught: cycles !== null, cycles, error, code, signal, left: staging(), stdout, stderr};
};

/** The verdict on one attempt: `pass`, `retry` (lost race), or `fail`, with why. */
const judge = (run, json) => {
	const {caught, cycles, error, code, signal, left, stdout, stderr} = run;
	if (error !== null) return ['fail', `duty-cycling the install failed: ${error.message}`];
	if (left.length > 0) return ['fail', `staging left: ${left.join(', ')}`];
	if (code !== 0 && code !== 130) {
		return ['fail', `exit ${code ?? `signal ${signal}`} (expected 130, or 0 for a lost race)`];
	}
	if (json && stdout.trim() !== '') {
		let doc;
		try {
			doc = JSON.parse(stdout);
		} catch {
			return ['fail', `stdout is a cut --json document: ${JSON.stringify(stdout.slice(-200))}`];
		}
		const claimed = doc?.error?.exit_code;
		if (claimed !== undefined && claimed !== code) {
			return ['fail', `the document says exit_code ${claimed}, the process exited ${code}`];
		}
	}
	if (!caught) return ['retry', `install ended (exit ${code}) before a staging tree was seen`];
	if (code === 0) return ['retry', 'the install published before the signal (exit 0)'];
	if (!stderr.includes(REMOVED_LINE)) {
		return ['retry', 'exit 130 without the removal line (the drain found nothing staged)'];
	}
	if (!json && /^error: /m.test(stderr)) {
		return ['fail', 'the install thread rendered an error after the drain fired'];
	}
	return [
		'pass',
		`caught frozen after ${cycles} cycle(s); exit 130, staging tree removed by the drain, no staging left`,
	];
};

let failed = false;
for (const json of [false, true]) {
	const mode = json ? '--json' : 'human';
	let verdict = null;
	let passes = 0;
	let attempts_run = 0;
	for (let attempt = 1; attempt <= ATTEMPTS; attempt++) {
		attempts_run = attempt;
		const run = await interrupt_once(json);
		const [kind, why] = judge(run, json);
		if (kind === 'retry') {
			console.error(`${mode} attempt ${attempt}: lost race — ${why}; retrying`);
			continue;
		}
		if (kind === 'pass') {
			passes++;
			console.log(`${mode} attempt ${attempt}: interrupted mid-staging (${passes}/${PASSES}) — ${why}`);
			if (passes < PASSES) continue;
			verdict = 'pass';
			break;
		}
		verdict = kind;
		console.error(
			`${mode} attempt ${attempt}: ${why}\n--- stderr\n${run.stderr}--- stdout\n${run.stdout}`,
		);
		break;
	}
	if (verdict === null) {
		console.error(
			`${mode}: caught the install mid-staging ${passes} of the ${PASSES} times needed in ${ATTEMPTS} attempts`,
		);
	} else if (verdict === 'pass') {
		console.log(`${mode}: ${passes}/${PASSES} passes in ${attempts_run} attempt(s)`);
	}
	if (verdict !== 'pass') failed = true;
}
process.exit(failed ? 1 : 0);
