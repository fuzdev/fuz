// The ESM import resolves through the sibling link (node_modules/localpkg-a ->
// ../../localpkg-a), and the registry dep resolves from the real tree beside it.
import {greet} from 'localpkg-a';
import pc from 'picocolors';

const got = greet('fuzi');
if (got !== 'hello, fuzi') {
	console.error(`unexpected greet() result: ${got}`);
	process.exit(1);
}
if (typeof pc.green !== 'function') {
	console.error('picocolors did not load');
	process.exit(1);
}
console.log(pc.green(got));
