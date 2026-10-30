// node toggle.mjs on|off <file>: creates or removes a flag file (a stand-in for "docker pause db" / "docker unpause db").
import { rmSync, writeFileSync } from 'node:fs';

const [mode, file] = process.argv.slice(2);
if (mode === 'on') writeFileSync(file, '');
else if (mode === 'off') rmSync(file, { force: true });
else process.exit(2);
