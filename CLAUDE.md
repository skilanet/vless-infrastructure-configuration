# CLAUDE.md — Working agreement for this repo

## How changes get delivered

The installer (`install.sh` + `lib/*.sh`) is for **fresh provisioning**, not for
patching a live box. Re-running modules every time we tweak a line is slow,
churns state, and risks regressions in unrelated parts of the system.

From now on, every change MUST be delivered as **two artifacts**:

1. **Source edits** — modify the relevant script(s) under `lib/`,
   `scripts/`, `admin-panel/`, etc. so the change is committed to the repo
   and will land on any *future* fresh install.

2. **A "live-fix" recipe** — a short, copy-pasteable block of shell commands
   the user runs **on the running server right now** to apply the same change
   in-place, without invoking `install.sh --rerun`.

Both must be produced for the same change. Never skip either one.

### What a live-fix recipe looks like

A live-fix is the minimum set of commands that brings the running server into
the state the edited script *would have* produced. It typically includes some
combination of:

- `sudo sed -i …` / `sudo tee …` / `sudoedit …` to patch a config in place
- `sudo install -m … -o … -g … …` to drop a new file with correct perms
- `sudo systemctl daemon-reload` + `sudo systemctl restart <unit>` when a unit
  file or its env changes
- `sudo -u <panel-user> …` to mutate panel-owned state
- `sudo chown … && sudo chmod …` to repair ownership/perms
- `rsync -a --delete <repo>/admin-panel/ /opt/xray-admin/` (excluding `venv/`)
  when only Python/template/static files changed
- `git -C /opt/vless-infrastructure-configuration pull` if the user wants to
  refresh the repo on the server first, then targeted commands

Always include verification at the end (`systemctl is-active …`,
`curl -fsSL http://127.0.0.1:$PANEL_PORT/health`, `journalctl -u … -n 20`,
etc.) so the user can confirm the fix landed.

### When a full `--rerun` is actually justified

Only suggest `install.sh --rerun <module>` when:

- The change touches **many** files inside one module *and* a live-fix would
  be longer/more error-prone than the rerun itself, **or**
- The module is genuinely idempotent and side-effect-free for this scenario
  (e.g. `01-prompts` to re-collect input), **or**
- The user explicitly asks for a rerun.

Default answer is: **edit the file, give a live-fix, do not rerun**.

### Format for the live-fix block

Present it as a single fenced bash block the user can paste, with brief
inline comments explaining each non-obvious step. Keep it tight — no
narration around it beyond a one-line preamble like:

> Применить на сервере прямо сейчас:

If the fix needs to be split across hosts (e.g. local edit then remote
apply), label each block clearly.

### Things to avoid

- Don't tell the user to "just rerun the installer" for one-line tweaks.
- Don't produce a live-fix that diverges from what the edited script does —
  they must match, otherwise the next fresh install will drift.
- Don't bundle unrelated fixes into one recipe. One bug → one edit + one
  recipe.
- Don't forget `daemon-reload` after touching unit files.
- Don't forget to restart the affected service.

## Style

User speaks Russian. Reply in Russian by default. Code comments and this
file stay English unless the user asks otherwise.
