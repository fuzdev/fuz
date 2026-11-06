// fuzi gate: the load-bearing esbuild check.
//
// esbuild's `postinstall` is skipped by fuzi (it is a pure perf optimization
// that renames the matching `@esbuild/<host>` ELF over the JS shim). esbuild
// also resolves that platform binary at runtime, so `transform` must work with
// the script skipped *given* `@esbuild/<host>` was placed. This asserts it.
//
// Run from inside a fuzi-installed fixture (cwd = the project root) so the bare
// `esbuild` import resolves against that tree's `node_modules`.
import {transform} from 'esbuild';

const {code} = await transform('let x = 1', {minify: true});
if (code.trim() !== 'let x=1;') {
	console.error(`esbuild.transform produced unexpected output: ${JSON.stringify(code)}`);
	process.exit(1);
}
console.log(`esbuild.transform OK -> ${JSON.stringify(code.trim())}`);
