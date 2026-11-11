# Detection evaluation

How well the deterministic detector (`backend/app/engines/detection`) separates instructions aimed at
an agent from ordinary content, measured on a labelled, reproducible corpus. This doc covers the
method, the corpus, the prediction rule, the current numbers, the tuning that produced them and the
known blind spots.

Everything in the corpus is inert. Credentials are canaries (`CTXOS-CANARY-…`), destinations are
reserved names (`.example`, `.invalid`, `.test`, `example.com`) or documentation IPs (`203.0.113.0/24`).
The evaluation never runs a command and never opens a network connection. It feeds text and
argument dictionaries to `analyze_content` and `analyze_tool_request`.

## How to run

All commands run from `backend/`:

```bash
.venv/bin/python -m tests.corpus.generate              # regenerate corpus.jsonl + tool_requests.jsonl
.venv/bin/python -m tests.corpus.generate --check      # exit 1 if the committed files are stale
.venv/bin/python -m tests.corpus.evaluate              # both splits, text report
.venv/bin/python -m tests.corpus.evaluate --split test # held-out numbers only
.venv/bin/python -m tests.corpus.evaluate --split dev --json --worst 20
.venv/bin/python -m pytest -q -p no:cacheprovider tests/unit/test_detection_corpus.py tests/unit/test_detection_tuning.py
```

The text report prints overall precision, recall, F1, false-positive rate and category accuracy. It
then gives a breakdown per family, per technique, per carrier and per language (per argument shape for
tool requests). It ends with the worst false positives, the worst false negatives and the detections
that carried an unexpected category, each listed with its sample id. If the committed corpus no longer
matches the generator, `evaluate` exits with code 2.

## Methodology

### Seeds

`backend/tests/corpus/seeds.py` holds the hand-written material:

- `INSTRUCTION_SEEDS`: 35 short malicious instructions in 11 families: instruction override, role
  impersonation, authority, credential access, exfiltration, tool coercion, concealment, MCP tool
  poisoning, cross-agent, permission escalation and multilingual. The multilingual family covers 11
  languages: es, fr, de, pt, it, nl, ru, zh, ja, ko and tr.
- `BENIGN_SEEDS`: 44 hard negatives. These are legitimate texts that share vocabulary with the attacks:
  security docs, JS/Python config code, shell and SSH docs, correspondence, mobile docs, prompt
  templates and changelogs. Kinds named `lookalike_*` look obfuscated but are ordinary data:
  - a base64 PNG data URI, base64 config data and base64 MIME text;
  - minified JS;
  - an OAuth redirect URL with percent-encoding;
  - emoji with zero-width joiners;
  - Russian and Greek prose;
  - a spaced-out banner, leet-looking product names, hash listings and mixed-case warnings.
- `TOOL_REQUEST_SEEDS`: 14 malicious and 19 benign tool requests. Four of the malicious ones
  (`tr-rc-*`) only recombine phrases from the other seeds.

### Carriers and transforms

`tests/corpus/carriers.py` wraps a payload in the document shape an agent actually ingests. There are
11 carriers:

- `plain`, `readme`;
- three web-page variants: `html_visible`, `html_display_none` (a `style="display:none"` element) and
  `html_comment`;
- `mcp_tool_description` (the description string the gateway scans);
- `tool_output_json` (serialised with Python's default `ensure_ascii=True`, as many MCP servers do);
- `email`, `code_comment`, `subagent_reply`;
- `pdf_text` (hard-wrapped at 68 columns, with a running header and footer).

The surrounding text uses no rule vocabulary. `test_carriers_alone_raise_no_alert` checks this.

`tests/corpus/transforms.py` applies the obfuscations that `normalize.py` claims to undo. There are 9
transforms: `none`, `zero_width`, `unicode_tags` (tag-block smuggling), `homoglyph` (Cyrillic
confusables), `leetspeak`, `spaced_letters`, `base64`, `url_encoding` (every byte percent-encoded) and
`mixed_case`. A transform that does not apply is skipped rather than producing a mislabelled sample.
Two examples: letter-level transforms on non-Latin scripts, and tag smuggling of non-ASCII text, which
the tag block cannot encode. URLs and file paths are left intact where an attacker needs them to work.

### Combination grid

`tests/corpus/generate.py` builds the grid deterministically:

- every malicious seed × every applicable transform, in the `plain` carrier;
- every malicious seed × every other carrier, untransformed;
- 4 more (carrier, transform) pairs per malicious seed, drawn with `random.Random` seeded from the seed
  id;
- every benign seed × every carrier, untransformed. Obfuscation-looking benign content comes from the
  `lookalike_*` seeds, not from transforms.

Tool requests are emitted in each argument shape the integrations report:

- `claude_code`, for example `Bash {command}`;
- `mcp`, for example `mcp__terminal__run_command {cmd}`;
- `sdk_nested` for shell commands: `run_shell {request: {script}}`.

### Splits

The dev/test split is assigned per seed, never per sample, so a seed never contributes to both splits
(`test_no_seed_appears_in_both_splits`). The generator groups the seeds by family. Within each group it
sorts them by `sha256` of the seed id and alternates between dev and test, starting from a
hash-chosen side. This keeps every family and every carrier/transform present in both splits. The
output (`corpus.jsonl`, `tool_requests.jsonl`) is committed. `test_committed_corpus_is_reproducible`
regenerates it and requires a byte-for-byte match.

### Tuning protocol

Rules were tuned by looking only at dev-split errors. The test split was evaluated once after dev
tuning finished. Its errors are reported below as blind spots and were not tuned away. There is one
disclosed exception, described under "Tuning changes".

## Prediction rule

**A sample is predicted malicious when the engine returns at least one hit with severity ≥ `medium`**
(`tests/corpus/metrics.py`, `PREDICTION_MIN_SEVERITY`). The reasons for this threshold:

- `low` is where the engine deliberately puts text that *describes* an attack: quoted, fenced or
  explanatory text, marked "(described, not issued)". The engine reports such hits but does not raise
  them as alarms. `info` makes no claim at all.
- `medium` is the threshold at which ingestion treats a hit as instructions aimed at the agent. Two
  places use it:
  - the `CTX-UNTRUSTED-INSTRUCTIONS` finding in `app/services/ingestion_context.py`;
  - the cross-agent contamination check in `app/services/ingestion_handlers.py` (`_injection_findings`).

  So `medium` is the operational alerting threshold, and that is what this evaluation measures.

**Category accuracy** asks one question of each malicious sample the engine flagged: did the expected
`FindingCategory` appear among its qualifying hits? Multi-step attacks legitimately produce several
categories; for example, sending a `.env` file out is both credential access and exfiltration.

## Corpus composition

| | dev | test | total |
|---|---:|---:|---:|
| content: malicious samples | 423 | 362 | 785 |
| content: benign samples | 242 | 242 | 484 |
| content: total | 665 | 604 | **1269** |
| tool requests: malicious / benign | 20 / 25 | 19 / 27 | 39 / 52 |
| malicious instruction seeds | 19 | 16 | 35 |
| benign content seeds | 22 | 22 | 44 |
| tool-request seeds (mal / benign) | 7 / 9 | 7 / 10 | 14 / 19 |

Non-English languages by split: dev has fr, it, ja, ko, tr and zh; test has de, es, nl, pt and ru.
Benign Greek (el) is in test, and the benign Russian, French, Spanish and German texts are spread
across both splits.

## Results

The **test split is the estimate**. The dev split was used for tuning, so its perfect score shows that
tuning removed every dev error; it is not evidence of real-world accuracy.

| | precision | recall | F1 | FP | FN | FPR | category acc. |
|---|---:|---:|---:|---:|---:|---:|---:|
| **content, test (final)** | **0.968** | **0.931** | **0.949** | 11 | 25 | 0.045 | 0.932 |
| content, test (first held-out run) | 0.966 | 0.931 | 0.948 | 12 | 25 | 0.050 | 0.932 |
| content, test (before tuning) | 0.887 | 0.870 | 0.879 | 40 | 47 | 0.165 | 0.933 |
| content, dev (tuned on) | 1.000 | 1.000 | 1.000 | 0 | 0 | 0.000 | 1.000 |
| content, dev (before tuning) | 0.817 | 0.931 | 0.871 | 88 | 29 | 0.364 | 0.992 |
| **tool requests, test (final)** | **0.850** | **0.895** | **0.872** | 3 | 2 | 0.111 | 1.000 |
| tool requests, test (before tuning) | 0.773 | 0.895 | 0.829 | 5 | 2 | 0.185 | 0.824 |
| tool requests, dev (tuned on) | 1.000 | 1.000 | 1.000 | 0 | 0 | 0.000 | 1.000 |

"First held-out run" is the single test evaluation made after dev tuning. "Final" adds the one
disclosed change described under "Tuning changes".

The overall targets were ≥ 0.90 precision and ≥ 0.85 recall on content. Content meets both. Tool-request
precision (0.850) is below 0.90. The tool set is small: all 3 false positives come from one benign
seed, `tr-ok-08` (`echo $PATH`), in its three argument shapes. That seed is on the test split, so it was
not tuned (see blind spots).

### Per technique (content, malicious samples, recall)

| technique | dev n | dev recall | test n | test recall |
|---|---:|---:|---:|---:|
| none | 209 | 1.000 | 176 | 0.932 |
| zero_width | 27 | 1.000 | 23 | 0.957 |
| unicode_tags | 23 | 1.000 | 19 | 0.842 |
| homoglyph | 28 | 1.000 | 20 | 0.950 |
| leetspeak | 21 | 1.000 | 26 | 0.923 |
| spaced_letters | 24 | 1.000 | 23 | 0.913 |
| base64 | 28 | 1.000 | 25 | 0.920 |
| url_encoding | 34 | 1.000 | 25 | 0.960 |
| mixed_case | 29 | 1.000 | 25 | 0.960 |

Most of the test misses are one seed, `coer-02`. It is missed under every carrier and transform, so it
lowers every row (see blind spots). Without it, every technique's test recall is ≥ 0.96.

### Per carrier (test)

| carrier | malicious | recall | benign FP |
|---|---:|---:|---:|
| plain | 138 | 0.935 | 1 |
| readme | 24 | 0.917 | 1 |
| html_visible | 20 | 0.950 | 1 |
| html_display_none | 22 | 0.955 | 2 |
| html_comment | 23 | 0.957 | 0 |
| mcp_tool_description | 20 | 0.950 | 1 |
| tool_output_json | 22 | 0.909 | 1 |
| email | 23 | 0.957 | 1 |
| code_comment | 21 | 0.905 | 1 |
| subagent_reply | 23 | 0.957 | 1 |
| pdf_text | 26 | 0.846 | 1 |

### Per language (malicious recall)

| split | language: recall |
|---|---|
| dev | en 1.000, fr 1.000, it 1.000, ja 1.000, ko 1.000, tr 1.000, zh 1.000 |
| test | en 0.905, de 1.000, es 1.000, nl 1.000, pt 0.955, ru 1.000 |

Test FPs are all English (11). The benign Greek, Russian, French, Spanish and German texts raise no
alert. The language rules exist only for the 13 languages in `rules.py` (`_ML`), and the corpus seeds
cover 11 of them. Hindi and Arabic rules have unit tests but no corpus seeds.

## Tuning changes (dev-driven)

All changes are in `backend/app/engines/detection/`. Each one has a benign near-miss test and a
still-detected positive in `tests/unit/test_detection_tuning.py`.

| change | why (dev evidence) |
|---|---|
| **CRED-001 requires credential-seeking intent.** Bare `process.env` no longer fires. The rule fires when the whole environment object reaches an output or transmit call (`console.log(process.env)`, `JSON.stringify(process.env)` sent somewhere), not on `process.env.NAME`, `process.env['NAME']` or destructuring. Bare mentions of `~/.ssh/id_rsa` and `~/.aws/credentials` now need a reading or sending verb. Public keys (`*.pub`) and example env files (`.env.example`, `.sample`, `.template`, `.dist`, `.defaults`) are excluded, as `redaction.is_sensitive_path` already treats them. | Mandated fix (JS config). Dev FPs `ben-13`, `ben-15`, `ben-16`, `ben-33`. |
| `TOOL-CRED-ENV`: `env VAR=1 cmd` is not an env dump. `env` counts only alone, piped or redirected. `process.env` gets the same intent rule as CRED-001. | Dev FP `tr-ok-09`; mandated `process.env` fix. |
| **Destructive commands have their own semantics.** All `TOOL-DESTRUCTIVE-*` rules report `suspicious_tool_use` instead of `permission_escalation`. `permission_escalation` now covers only `TOOL-AGENT-CONFIG-WRITE`, `TOOL-PERSIST` and `TOOL-REVSHELL`. As a result, "Deny destructive shell commands" (matched by rule-id glob) and "Deny agent config tampering and privilege escalation" (matched by category) each match only their own intent, and disabling one changes the decision. `app/engines/policy/builtin.py` is updated; built-ins cannot be deleted (409), only disabled. | Mandated fix. Covered by `test_destructive_command_matches_only_the_destructive_policy` and `test_privilege_escalation_matches_only_the_escalation_policy`. |
| EXFIL-001: curl/wget counts as exfiltration only when it carries data out (`-d`, `--data*`, `-F`, `-T`, `--upload-file`, `--post-*`, `-X POST/PUT`, or "with the data/contents/…"). Downloads are not exfiltration. | Dev FPs `ben-04`, `ben-14`. |
| PI-ROLE-002: "developer mode" and "jailbreak" fire only when aimed at the agent ("you are in developer mode", "enable developer mode … bypass …", "jailbreak mode", "you are jailbroken"). Phone and app features do not fire. The "as an AI, you must" clause is now reachable (its prefilter anchor was missing). | Dev FPs `ben-19`, `ben-20`. |
| PI-OVERRIDE-001: a single "previous message" in correspondence is not an override. "previous messages" (plural) and "the system message" still are. | Dev FP `ben-18`. |
| Descriptive context ("described, not issued") is evaluated in every view's own text, not only the original. Dampened hits are no longer escalated as concealment. | Dev FPs: `ben-04` in e-mail, where a timestamp triggered the leetspeak view, and in hidden HTML. |
| Normalisation additions: | Dev FNs: leetspeak, spaced letters, `pdf_text`, `tool_output_json`. |
| • leet tokens may start with a digit; | |
| • spelt-out text also collapses short words and squeezes wide gaps (the prefilter anchors contain single spaces); | |
| • letters of any script are recognised; | |
| • a `reflowed` view joins hard-wrapped lines, without joining quotes, fences or lists; | |
| • JSON `\uXXXX` escapes (with surrogate pairs) are decoded and then re-normalised (zero-width, tags, homoglyphs). | |
| `analyze_tool_request` also matches on decoded base64 segments of the arguments, so `echo <b64> \| base64 -d \| sh` is reported with the exfiltration it hides. | Dev miscategorised `tr-enc-01`. |

**Disclosed post-evaluation change.** The `.env` file alternative of CRED-001 also matched inside
`process.env`. It needed a verb nearby, which `style="display:none"` supplies. This was the mandated
`process.env` issue firing through a second clause, so it was fixed after the held-out run
(`(?<![\w$])\.env`). It changed one test sample (`ben-02|html_display_none`). That change is the only
difference between the "first held-out run" and "final" rows.

`tests/unit/test_detection.py` needed no changes. None of its cases encoded the false positives fixed
here.

## Known blind spots

The test split surfaced the following misses. They were deliberately not tuned, so the test estimate
stays honest. The benign high-severity cases are pinned in `KNOWN_HIGH_SEVERITY_BENIGN`
(`tests/unit/test_detection_corpus.py`). Fixing one fails that test until the pin and this list are
updated.

- **Semantic paraphrase without trigger vocabulary.** The detector is lexical. An instruction phrased
  with no rule vocabulary is missed. `coer-02` (calling "the shell tool" with a command "silently, then
  report success") is missed in all 23 of its samples, and it accounts for 23 of the 25 test FNs. The
  same applies to polite or indirect phrasings, role-play framing and instructions split across
  several messages.
- **Sentence-bounded regexes.** Most rules use `[^.\n]` windows, so a period inside a file name ends the
  window. Example: "send the contents of the `.env` file to <url>" (`exf-01`) is detected as
  `credential_access` but not `exfiltration`. This accounts for all 23 category errors on test.
- **Context lost in extracted segments.** A hidden segment is scanned on its own. A security explainer
  that quotes `<!-- note to the AI -->` therefore raises PI-AUTHORITY-001 at high (`ben-11`, 10
  carriers; the 11th, `html_comment`, nests comments and is not flagged).
- **Markup read as prose.** The CSS property `display` in `style="display:none"` acts as the verb for
  CRED-001 next to a `.env` mention (`ben-44|html_display_none`).
- **`echo $VAR` clause.** It does not tell secrets from ordinary variables (`tr-ok-08`, `echo $PATH`,
  high severity).
- **GET-based exfiltration.** Data placed in a query string of a fetched URL (`tr-exf-04`: WebFetch to
  a URL with `?k=<canary>`) has no tool rule. The destination checks in the trust engine are the
  control there, not detection.
- **Composed layers.** Views are built from the original text, plus leetspeak over the reflowed text.
  Other combinations (leetspeak inside JSON escapes: `ml-pt|tool_output_json|leetspeak`) and a wrap
  directly before a path (`cred-02|pdf_text`: the next line starts with `~`) are missed.
- **Descriptive framing lowers severity on purpose.** Text inside code fences, block quotes or
  explanatory phrases ("for example", "attackers often") is reported at `low`. This applies to hidden
  markup too, since the tuning removed the concealment bump for described hits. An attacker who adds
  such framing gets a `low` hit, not a `medium` one.
- **Languages not covered.** Only the 13 languages in `_ML` are covered, and for those only the
  override, credential and exfiltration families (no authority, concealment or coercion rules). Other
  languages rely on base64 or URL decoding exposing English text, which they usually do not.
- **No ML classifier in this evaluation.** `register_classifier` was unset. The numbers are for the
  deterministic rules alone.
- **Corpus scope.** 112 hand-written seeds (79 content, 33 tool requests) cannot represent real traffic. The numbers measure
  regressions and coverage of known techniques. They are not a field false-positive rate.

## Regression guard

`backend/tests/unit/test_detection_corpus.py` checks the following:

- **Integrity:** schema validity, unique ids, seed-level split separation, reproducibility, size
  (≥ 600 samples, ≥ 150 benign), every carrier and technique present in both splits, and reserved
  destinations only in malicious samples.
- **Test-split floors** (just below the measured numbers):
  - content: precision ≥ 0.96, recall ≥ 0.92, category accuracy ≥ 0.92, plus the absolute ≥ 0.90 / ≥ 0.85 targets;
  - tool requests: precision ≥ 0.84, recall ≥ 0.89.
- **Dev split** stays ≥ 0.99.
- **Per-technique recall** stays ≥ 0.80.
- **No benign sample reaches high severity** except the pinned blind spots. The obfuscation lookalikes
  raise no alert at all.

## Adding samples

1. Add a seed to `backend/tests/corpus/seeds.py`:
   - malicious: `{"id", "family", "category", "lang", "text"}` in `INSTRUCTION_SEEDS`;
   - benign: `{"id", "kind", "text"}` (plus `"lang"` if not English) in `BENIGN_SEEDS`; a `lookalike_*`
     kind for obfuscation-looking data;
   - tool request: `{"id", "malicious", "category", "tool", "arguments"}` in `TOOL_REQUEST_SEEDS`.

   Use canaries and reserved destinations only. Keep ids unique and stable: the split depends on the
   id.
2. Run `.venv/bin/python -m tests.corpus.generate`, then commit the regenerated `corpus.jsonl` and
   `tool_requests.jsonl`.
3. Run `.venv/bin/python -m tests.corpus.evaluate --split dev`. If you tune on the result, change rules
   based on dev errors only.
4. Re-measure the test split once. Update the tables above, and change the floors or the
   `KNOWN_HIGH_SEVERITY_BENIGN` pin only to reflect the new measured numbers. Never lower a floor to
   make a regression pass.

To add a carrier or transform, add a function to `carriers.py` or `transforms.py` and register it in
`CARRIERS` or `TRANSFORMS`. A transform returns `None` where it does not apply.
