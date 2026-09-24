#!/usr/bin/env python3
"""Sweep the heredoc/exec combination space and report every divergence.

guards.bats pins behaviours one at a time, each with the reason it exists. This
does the other job: it walks the *product* of the things that decide how a body
is read — who consumes it, which exec API it calls, how the binary is spelled,
what writes the script that runs — and prints a table. That is what found the
holes it now pins; a one-line case here is cheap enough that the combination
nobody thought of gets written down anyway.

    python3 tests/matrix.py             # table, exit 1 on any divergence
    python3 tests/matrix.py -v          # with the prompt text of every ask
    python3 tests/matrix.py -k docker   # only cases whose label matches

No dependencies beyond the standard library, and it runs the hook under
/bin/bash — the shebang's interpreter, i.e. bash 3.2 on macOS, where the string
handling this guard is careful about behaves differently than under bash 5.
"""
import argparse
import json
import os
import subprocess
import sys

TESTS = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(TESTS)
HOOK = os.path.join(ROOT, "hooks", "env-guard.sh")
STUBS = os.path.join(TESTS, "stubs")

# The same environment guards.bats builds: stubbed binaries for anything whose
# answer would otherwise come from this machine (kube context, docker endpoint,
# TF workspace), and an allowlist path that deliberately does not exist, so a
# rule in the real ~/.claude/guard-allow.conf cannot quietly pass a case.
ENV = dict(os.environ)
ENV["PATH"] = STUBS + os.pathsep + ENV.get("PATH", "")
ENV["KUBE_TEST_CONTEXT"] = "wonka-factory"
ENV["GUARD_ALLOW_FILE"] = os.path.join(TESTS, "no-such-allowlist.conf")
for leaked in ("OS_CLOUD", "OS_CLOUD_NAME", "KUBECONFIG", "ARGOCD_SERVER"):
    ENV.pop(leaked, None)


def run(command, cwd="/tmp"):
    """(decision, reason) for one command: 'PASS', 'ASK', or '?' with the raw output."""
    payload = json.dumps({"cwd": cwd, "tool_input": {"command": command}})
    proc = subprocess.run(["/bin/bash", HOOK], input=payload, capture_output=True,
                          text=True, env=ENV, timeout=30)
    out = proc.stdout.strip()
    if not out:
        return "PASS", ""
    try:
        decision = json.loads(out)["hookSpecificOutput"]
        return decision["permissionDecision"].upper(), decision["permissionDecisionReason"]
    except (ValueError, KeyError):
        return "?", out


# --- the cases ---------------------------------------------------------------
#
# Fictional names throughout (wonka-factory, hamster-runner-1, pancake-service),
# per the same rule guards.bats follows: a test that names a real cluster is one
# copy of that name too many.

KDEL_PY = "import subprocess\nsubprocess.run(['kubectl','delete','pod','hamster-runner-1'])"
KDEL_SH = "kubectl --context wonka-factory delete pod hamster-runner-1"
PY = "python3 - <<'PY'\n%s\nPY"

GROUPS = [
    ("A. consumers — the body is `kubectl delete` via an exec API", [
        ("python3 -            (baseline)", PY % KDEL_PY, "ASK"),
        ("python -             ", "python - <<'PY'\n%s\nPY" % KDEL_PY, "ASK"),
        ("python3.12 -         ", "python3.12 - <<'PY'\n%s\nPY" % KDEL_PY, "ASK"),
        ("python3.11 -         ", "python3.11 - <<'PY'\n%s\nPY" % KDEL_PY, "ASK"),
        ("/usr/bin/python3 -   ", "/usr/bin/python3 - <<'PY'\n%s\nPY" % KDEL_PY, "ASK"),
        ("env python3 -        ", "env python3 - <<'PY'\n%s\nPY" % KDEL_PY, "ASK"),
        ("uv run python -      ", "uv run python - <<'PY'\n%s\nPY" % KDEL_PY, "ASK"),
        ("poetry run python -  ", "poetry run python - <<'PY'\n%s\nPY" % KDEL_PY, "ASK"),
        ("uvx python -         ", "uvx python - <<'PY'\n%s\nPY" % KDEL_PY, "ASK"),
        ("node -               ", "node - <<'JS'\nrequire('child_process').execSync('kubectl delete pod hamster-runner-1')\nJS", "ASK"),
        ("npx tsx -            ", "npx tsx - <<'TS'\nrequire('child_process').execSync('kubectl delete pod hamster-runner-1')\nTS", "ASK"),
        ("ts-node -            ", "ts-node - <<'TS'\nrequire('child_process').execSync('kubectl delete pod hamster-runner-1')\nTS", "ASK"),
        ("ruby -               ", "ruby - <<'RB'\nsystem(\"kubectl delete pod hamster-runner-1\")\nRB", "ASK"),
        ("perl -               ", "perl - <<'PL'\nsystem(\"kubectl delete pod hamster-runner-1\");\nPL", "ASK"),
        ("php -                ", "php - <<'PHP'\nshell_exec('kubectl delete pod hamster-runner-1');\nPHP", "ASK"),
        ("Rscript -            ", "Rscript - <<'R'\nsystem(\"kubectl delete pod hamster-runner-1\")\nR", "ASK"),
        ("lua -                ", "lua - <<'LUA'\nos.execute('kubectl delete pod hamster-runner-1')\nLUA", "ASK"),
        ("osascript -          ", "osascript - <<'AS'\ndo shell script \"kubectl delete pod hamster-runner-1\"\nAS", "ASK"),
        ("awk -f -             ", "awk -f - <<'AWK'\nBEGIN{system(\"kubectl delete pod hamster-runner-1\")}\nAWK", "ASK"),
        ("gawk -f -            ", "gawk -f - <<'AWK'\nBEGIN{system(\"kubectl delete pod hamster-runner-1\")}\nAWK", "ASK"),
        ("julia -              ", "julia - <<'JL'\nrun(`kubectl delete pod hamster-runner-1`)\nJL", "ASK"),
        ("expect -f -          ", "expect -f - <<'EXP'\nspawn kubectl delete pod hamster-runner-1\nEXP", "ASK"),
        ("fish (shell)         ", "fish <<'EOF'\n%s\nEOF" % KDEL_SH, "ASK"),
        ("pwsh (shell)         ", "pwsh <<'EOF'\n%s\nEOF" % KDEL_SH, "ASK"),
        ("bash (shell, control)", "bash <<'EOF'\n%s\nEOF" % KDEL_SH, "ASK"),
    ]),
    ("B. exec APIs inside python3 / ruby / node", [
        ("py subprocess.run      ", PY % KDEL_PY, "ASK"),
        ("py os.system           ", "python3 - <<'PY'\nimport os\nos.system('kubectl delete pod x')\nPY", "ASK"),
        ("py os.execvp           ", "python3 - <<'PY'\nimport os\nos.execvp('kubectl',['kubectl','delete','pod','x'])\nPY", "ASK"),
        ("py asyncio subprocess  ", "python3 - <<'PY'\nimport asyncio\nasyncio.run(asyncio.create_subprocess_exec('kubectl','delete','pod','x'))\nPY", "ASK"),
        ("py sh module           ", "python3 - <<'PY'\nimport sh\nsh.kubectl('delete','pod','x')\nPY", "ASK"),
        ("py plumbum             ", "python3 - <<'PY'\nfrom plumbum import local\nlocal['kubectl']['delete','pod','x']()\nPY", "ASK"),
        ("py fabric/invoke       ", "python3 - <<'PY'\nfrom invoke import run\nrun('kubectl delete pod x')\nPY", "ASK"),
        ("rb backticks           ", "ruby - <<'RB'\nputs `kubectl delete pod x`\nRB", "ASK"),
        ("rb %x[]                ", "ruby - <<'RB'\nputs %x[kubectl delete pod x]\nRB", "ASK"),
        ("rb Open3               ", "ruby - <<'RB'\nOpen3.capture2('kubectl','delete','pod','x')\nRB", "ASK"),
        ("pl backticks           ", "perl - <<'PL'\nmy $o = `kubectl delete pod x`;\nPL", "ASK"),
        ("pl open -|             ", "perl - <<'PL'\nopen(my $fh, '-|', 'kubectl delete pod x');\nPL", "ASK"),
        ("php backticks          ", "php - <<'PHP'\n$o = `kubectl delete pod x`;\nPHP", "ASK"),
        ("node execSync          ", "node - <<'JS'\nconst {execSync}=require('child_process');execSync('kubectl delete pod x')\nJS", "ASK"),
        ("node execa             ", "node - <<'JS'\nimport {execa} from 'execa';await execa('kubectl',['delete','pod','x'])\nJS", "ASK"),
        ("node zx $``            ", "node - <<'JS'\nawait $`kubectl delete pod x`\nJS", "ASK"),
        ("bun Bun.spawn          ", "bun - <<'JS'\nBun.spawn(['kubectl','delete','pod','x'])\nJS", "ASK"),
        ("deno Deno.Command      ", "deno run - <<'TS'\nnew Deno.Command('kubectl',{args:['delete','pod','x']}).spawn()\nTS", "ASK"),
        ("R system2              ", "Rscript - <<'R'\nsystem2('kubectl', c('delete','pod','x'))\nR", "ASK"),
    ]),
    ("C. how the body spells the binary", [
        ("bare name in list      ", PY % KDEL_PY, "ASK"),
        ("absolute path          ", "python3 - <<'PY'\nimport subprocess\nsubprocess.run(['/usr/local/bin/kubectl','delete','pod','x'])\nPY", "ASK"),
        ("relative ./path        ", "python3 - <<'PY'\nimport subprocess\nsubprocess.run(['./bin/kubectl','delete','pod','x'])\nPY", "ASK"),
        ("shell string           ", "python3 - <<'PY'\nimport subprocess\nsubprocess.run('kubectl delete pod x',shell=True)\nPY", "ASK"),
        ("via variable           ", "python3 - <<'PY'\nimport subprocess\nBIN='kubectl'\nsubprocess.run([BIN,'delete','pod','x'])\nPY", "ASK"),
        ("f-string               ", "python3 - <<'PY'\nimport subprocess\nsubprocess.run(f'kubectl delete pod {name}',shell=True)\nPY", "ASK"),
        ("sudo prefix            ", "python3 - <<'PY'\nimport subprocess\nsubprocess.run(['sudo','kubectl','delete','pod','x'])\nPY", "ASK"),
    ]),
    ("D. write-then-execute", [
        ("cat >script && bash it ", "cat > /tmp/deploy.sh <<'EOF'\n%s\nEOF\nbash /tmp/deploy.sh" % KDEL_SH, "ASK"),
        ("tee script; sh it      ", "tee /tmp/d.sh <<'EOF'\n%s\nEOF\nsh /tmp/d.sh" % KDEL_SH, "ASK"),
        ("cat >script; chmod;run ", "cat > /tmp/d.sh <<'EOF'\n%s\nEOF\nchmod +x /tmp/d.sh && /tmp/d.sh" % KDEL_SH, "ASK"),
        ("py writes then runs    ", "python3 - <<'PY'\nimport os\nopen('/tmp/d.sh','w').write('kubectl delete pod x')\nos.system('bash /tmp/d.sh')\nPY", "ASK"),
        ("py writes, shell runs  ", "python3 - <<'PY'\nopen('/tmp/d.sh','w').write('%s')\nPY\nbash /tmp/d.sh" % KDEL_SH, "ASK"),
        ("py writes an unknown   ", "python3 - <<'PY'\nopen('/tmp/d.sh','w').write(render_template(env))\nPY\nbash /tmp/d.sh", "ASK"),
        ("curl >script, then run ", "curl -s https://wonka.test/d.sh > /tmp/d.sh && bash /tmp/d.sh", "ASK"),
    ]),
    ("E. read-only work wrapped in an interpreter", [
        ("py git grep            ", "python3 - <<'PY'\nimport subprocess\nsubprocess.run(['git','grep','-n','foo','--','src'])\nPY", "PASS"),
        ("py git log             ", "python3 - <<'PY'\nimport subprocess\nsubprocess.run(['git','log','--oneline','-20'])\nPY", "PASS"),
        ("py kubectl get         ", "python3 - <<'PY'\nimport subprocess\nsubprocess.run(['kubectl','get','pods','-A'])\nPY", "PASS"),
        ("py terraform show      ", "python3 - <<'PY'\nimport subprocess\nsubprocess.run(['terraform','show'])\nPY", "PASS"),
        ("py terraform state list", "python3 - <<'PY'\nimport subprocess\nsubprocess.run(['terraform','state','list'])\nPY", "PASS"),
        ("py helm list           ", "python3 - <<'PY'\nimport subprocess\nsubprocess.run(['helm','list','-A'])\nPY", "PASS"),
        ("py gh pr list          ", "python3 - <<'PY'\nimport subprocess\nsubprocess.run(['gh','pr','list'])\nPY", "PASS"),
        ("py path'd git status   ", "python3 - <<'PY'\nimport subprocess\nsubprocess.run(['cat','/repo/.git/config'])\nsubprocess.run(['git','status'])\nPY", "PASS"),
        ("node git log           ", "node - <<'JS'\nrequire('child_process').execSync('git log --oneline')\nJS", "PASS"),
        ("rb backtick git log    ", "ruby - <<'RB'\nputs `git log --oneline -20`\nRB", "PASS"),
        ("bash heredoc kubectl get", "bash <<'EOF'\nkubectl --context wonka-factory get pods\nEOF", "PASS"),
        ("py writes yaml only    ", "python3 - <<'PY'\nopen('chart.yaml','w').write('name: kubectl-helper')\nPY", "PASS"),
        ("py reads a script, runs", "python3 - <<'PY'\nprint(open('/tmp/d.sh').read())\nPY\nbash /tmp/d.sh", "PASS"),
    ]),
    ("F. non-heredoc shapes, for contrast", [
        ("bash -c mutation       ", "bash -c 'kubectl --context wonka-factory delete pod x'", "ASK"),
        ("bash herestring        ", "bash <<< 'kubectl --context wonka-factory delete pod x'", "ASK"),
        ("echo | bash            ", "echo 'kubectl --context wonka-factory delete pod x' | bash", "ASK"),
        ("ssh host 'mutation'    ", "ssh deploy@wonka-host 'kubectl --context wonka-factory delete pod x'", "ASK"),
        ("py -c mutation         ", "python3 -c \"import os;os.system('kubectl --context wonka-factory delete pod x')\"", "ASK"),
        ("bash -c read-only      ", "bash -c 'kubectl --context wonka-factory get pods'", "PASS"),
    ]),
    ("G. transports and wrapper prefixes", [
        ("docker exec -i box python3 -", "docker exec -i box python3 - <<'PY'\n%s\nPY" % KDEL_PY, "ASK"),
        ("docker exec -i box bash     ", "docker exec -i box bash <<'EOF'\n%s\nEOF" % KDEL_SH, "ASK"),
        ("kubectl exec -i pod -- py3  ", "kubectl exec -i pod -- python3 - <<'PY'\n%s\nPY" % KDEL_PY, "ASK"),
        ("ssh host python3 -          ", "ssh deploy@wonka-host python3 - <<'PY'\n%s\nPY" % KDEL_PY, "ASK"),
        ("sudo python3 -              ", "sudo python3 - <<'PY'\n%s\nPY" % KDEL_PY, "ASK"),
        ("time python3 -              ", "time python3 - <<'PY'\n%s\nPY" % KDEL_PY, "ASK"),
        ("nohup python3 -             ", "nohup python3 - <<'PY'\n%s\nPY" % KDEL_PY, "ASK"),
        ("xargs -I@ python3 -         ", "echo x | xargs -I@ python3 - <<'PY'\n%s\nPY" % KDEL_PY, "ASK"),
        ("timeout 60 python3 -        ", "timeout 60 python3 - <<'PY'\n%s\nPY" % KDEL_PY, "ASK"),
        ("FOO=bar python3 -           ", "FOO=bar python3 - <<'PY'\n%s\nPY" % KDEL_PY, "ASK"),
    ]),
    ("H. heredocs mixed with pipes, redirects and each other", [
        ("py heredoc piped to tee   ", "python3 - <<'PY' | tee /tmp/log\n%s\nPY" % KDEL_PY, "ASK"),
        ("py heredoc redirected >|  ", "python3 - <<'PY' >| /tmp/out.json\n%s\nPY" % KDEL_PY, "ASK"),
        ("data heredoc then py one  ", "cat > notes.md <<'DOC'\nplain prose\nDOC\npython3 - <<'PY'\n%s\nPY" % KDEL_PY, "ASK"),
        ("py one then data heredoc  ", "python3 - <<'PY'\n%s\nPY\ncat > notes.md <<'DOC'\nprose\nDOC" % KDEL_PY, "ASK"),
        ("two py heredocs, 2nd bad  ", "python3 - <<'A'\nprint(1)\nA\npython3 - <<'B'\n%s\nB" % KDEL_PY, "ASK"),
        ("py heredoc in && chain    ", "ls && python3 - <<'PY'\n%s\nPY" % KDEL_PY, "ASK"),
        ("indented <<- delimiter    ", "python3 - <<-'PY'\n\t%s\n\tPY" % KDEL_PY, "ASK"),
        ("unquoted delim + subproc  ", "python3 - <<PY\n%s\nPY" % KDEL_PY, "ASK"),
    ]),
    ("I. data consumers must stay silent", [
        ("cat > runbook             ", "cat > runbook.md <<'DOC'\nrun `%s` by hand\nDOC" % KDEL_SH, "PASS"),
        ("cat >| runbook            ", "cat >| runbook.md <<'DOC'\nrun `%s` by hand\nDOC" % KDEL_SH, "PASS"),
        ("git commit -F -           ", "git commit -F - <<'MSG'\nfix: stop running %s\nMSG" % KDEL_SH, "PASS"),
        ("jq -f -                   ", "jq -f - <<'JQ'\n.items[] | select(.name==\"kubectl-delete-job\")\nJQ", "PASS"),
        ("kubectl apply -f - (data) ", "kubectl --context orbstack apply -f - <<'YAML'\nkind: Pod\nname: kubectl-delete-helper\nYAML", "PASS"),
        ("docker exec -i box tee    ", "docker exec -i box tee /etc/runbook <<'EOF'\n%s\nEOF" % KDEL_SH, "PASS"),
        ("awk '{print}' (data)      ", "awk /delete/ <<'EOF'\nsystem(\"%s\")\nEOF" % KDEL_SH, "PASS"),
        ("py heredoc writing yaml   ", "python3 - <<'PY'\nopen('c.yaml','w').write('name: kubectl-delete-helper')\nPY", "PASS"),
        ("py markdown with backticks", "python3 - <<'PY'\nopen('runbook.md','w').write('run `%s`')\nPY" % KDEL_SH, "PASS"),
    ]),
    ("J. a prefix on the opening line must not hide the consumer", [
        ("python3 -            (control)", PY % KDEL_PY, "ASK"),
        ("ls && python3 -               ", "ls && python3 - <<'PY'\n%s\nPY" % KDEL_PY, "ASK"),
        ("cd /repo && python3 -         ", "cd /repo && python3 - <<'PY'\n%s\nPY" % KDEL_PY, "ASK"),
        ("ls ; python3 -                ", "ls ; python3 - <<'PY'\n%s\nPY" % KDEL_PY, "ASK"),
        ("ls || python3 -               ", "ls || python3 - <<'PY'\n%s\nPY" % KDEL_PY, "ASK"),
        ("echo hi | python3 -           ", "echo hi | python3 - <<'PY'\n%s\nPY" % KDEL_PY, "ASK"),
        ("bash            (control)     ", "bash <<'EOF'\n%s\nEOF" % KDEL_SH, "ASK"),
        ("cd /repo && bash              ", "cd /repo && bash <<'EOF'\n%s\nEOF" % KDEL_SH, "ASK"),
        ("ls ; bash                     ", "ls ; bash <<'EOF'\n%s\nEOF" % KDEL_SH, "ASK"),
        ("ssh host bash (control)       ", "ssh wonka-host bash <<'EOF'\n%s\nEOF" % KDEL_SH, "ASK"),
        ("cd /r && ssh host bash        ", "cd /r && ssh wonka-host bash <<'EOF'\n%s\nEOF" % KDEL_SH, "ASK"),
        ("if-then bash                  ", "if true; then bash <<'EOF'\n%s\nEOF\nfi" % KDEL_SH, "ASK"),
        ("for-do python3 -              ", "for f in a; do python3 - <<'PY'\n%s\nPY\ndone" % KDEL_PY, "ASK"),
    ]),
    ("K. the expansion path survives the same prefix", [
        ("py unquoted + $()  (control)  ", "python3 - <<PY\nx = \"$(%s)\"\nPY" % KDEL_SH, "ASK"),
        ("ls && py unquoted + $()       ", "ls && python3 - <<PY\nx = \"$(%s)\"\nPY" % KDEL_SH, "ASK"),
        ("ls && cat > f unquoted + $()  ", "ls && cat > f.txt <<EOF\n$(%s)\nEOF" % KDEL_SH, "ASK"),
    ]),
    ("L. write-then-run behind a prefix or a noclobber redirect", [
        ("cat>f && bash f    (control)  ", "cat > /tmp/d.sh <<'EOF'\n%s\nEOF\nbash /tmp/d.sh" % KDEL_SH, "ASK"),
        ("cd /r && cat>f && bash f      ", "cd /r && cat > /tmp/d.sh <<'EOF'\n%s\nEOF\nbash /tmp/d.sh" % KDEL_SH, "ASK"),
        ("echo >| f && bash f           ", "echo '%s' >| /tmp/d.sh && bash /tmp/d.sh" % KDEL_SH, "ASK"),
        ("cat >| f heredoc && bash f    ", "cat >| /tmp/d.sh <<'EOF'\n%s\nEOF\nbash /tmp/d.sh" % KDEL_SH, "ASK"),
        ("kubectl get >| out.txt        ", "kubectl --context wonka-factory get pods >| /tmp/out.txt", "PASS"),
        ("gen > log && bash other       ", "python3 gen.py > /tmp/build.log && bash /tmp/other.sh", "PASS"),
    ]),
]


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-v", "--verbose", action="store_true",
                    help="print the prompt text of every ask")
    ap.add_argument("-k", metavar="PATTERN", default="",
                    help="only run cases whose group or label contains PATTERN")
    args = ap.parse_args(argv)

    if not os.access(HOOK, os.X_OK):
        print("no executable hook at %s" % HOOK, file=sys.stderr)
        return 2
    # A stub that is not executable is silently skipped by `command -v`, and the
    # case then passes against whatever this machine happens to have installed —
    # a false pass that looks exactly like a real one.
    for stub in sorted(os.listdir(STUBS)):
        if not os.access(os.path.join(STUBS, stub), os.X_OK):
            print("stub %s is not executable; chmod +x it" % stub, file=sys.stderr)
            return 2

    total = wrong = 0
    for title, cases in GROUPS:
        shown = [c for c in cases if args.k in title or args.k in c[0]]
        if not shown:
            continue
        print("\n=== %s %s" % (title, "=" * max(0, 62 - len(title))))
        for label, command, want in shown:
            got, reason = run(command)
            total += 1
            if got != want:
                wrong += 1
            print("%s %-4s (want %-4s) %s" % ("!!" if got != want else "  ", got, want, label))
            if args.verbose and reason:
                print("        -> %s" % reason[:150])

    print("\n%d case(s), %d diverge from expectation" % (total, wrong))
    return 1 if wrong else 0


if __name__ == "__main__":
    sys.exit(main())
