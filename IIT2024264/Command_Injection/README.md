# Frame — image-processing security lab

A thumbnail-export studio demonstrating **in-band OS command injection**. Vulnerable and secured panels process the same request using ImageMagick, showing real image exports and command output.

## Run

Requires **Python 3**, **ImageMagick** (`magick` or `convert`), and a non-root Linux account. No pip packages needed.

```bash
cd /home/d1nu/CS/netcheck
python3 server.py
```

Open **http://127.0.0.1:8000** and keep the terminal running. Use the Python server rather than Live Server or opening the HTML directly. After backend edits, press **Ctrl+C**, restart, and refresh.

If port 8000 is occupied, use `python3 server.py --port 8001` and open **http://127.0.0.1:8001**.

The vulnerable endpoint executes shell input with your account's permissions. Keep this lab local to your own lab machine; do not publish or tunnel it.

## Demo

Use the sample image or upload a PNG/JPEG up to **3 MiB**. Choose a width of **320**, **480**, or **720** pixels and color or grayscale processing.

1. Export `postcard.png`: both panels should show downloadable thumbnails.
2. Try the injection presets below: the vulnerable panel returns command output; the secure panel rejects the same input.
3. Select **RCE: write proof** and open the actual proof-file link.
4. Show the runtime section, then select **Permission boundary** to demonstrate a denied write.
5. Open the commented vulnerable and secured blocks in `server.py`. Capture the side-by-side results for your video/report.

| Filename | Vulnerable behavior |
| --- | --- |
| `postcard.png; id` | Runs the export, then `id`, regardless of export success. |
| `postcard.png && whoami` | Runs `whoami` if the export succeeds. |
| `postcard.png \| id` | Creates a pipeline; commands can run concurrently, and `id` prints the process identity. |
| `postcard$(id >&2).png` | Runs `id` before ImageMagick; stderr captures its output while the filename remains `postcard.png`. |
| ``postcard`id >&2`.png`` | Uses backtick command substitution with the same effect. |

The RCE preset creates a harmless marker in the request's temporary directory and reads it back:

```text
postcard.png; printf FRAME_RCE_DEMO > "$FRAME_JOB_DIR/proof.txt"; cat "$FRAME_JOB_DIR/proof.txt"
```

The proof card appears only when the backend finds the actual file. The identity commands already establish command execution; this adds a visible filesystem effect.

## Root cause and mitigation

**Vulnerable:** the backend concatenates the unquoted export filename into a command and uses `shell=True`. Shell operators become executable syntax. Output returning in the HTTP response makes this the **in-band** variant.

**Secured:** a filename allow-list accepts simple PNG basenames, and a fixed executable receives separate arguments with `shell=False`. Injected filenames are rejected before a process starts. Code comments identify the execution sink, the secured path, and shared validation/output handling. Browser output uses `textContent` rather than HTML interpretation.

**Other defenses:** use a native image library to avoid external commands, validate processing options, and apply least privilege. Character blacklists are incomplete; passing arguments to `sh -c` still invokes a shell.

## Least privilege

The runtime section reports the actual account, UID/GID, and restrictions. Desktop execution refuses root, enables Linux no-new-privileges, creates private temporary files, and gives child processes a minimal environment. These controls do not revoke the account's existing file access.

The permissions preset attempts:

```text
postcard.png; printf FRAME_RCE_DEMO > "$FRAME_PROTECTED/proof.txt"
```

The vulnerable path exports the image but receives a write error. The secure path rejects the filename. The local protected directory uses mode `0555`; its owner could change those permissions, so it is a **permissions demonstration, not a sandbox**. Least privilege limits damage; it does not fix injection.

## Files

- `server.py`: HTTP API, image processing, and commented execution paths.
- `index.html`: dark studio, presets, results, and runtime display.
- `assets/sample.png`: bundled image.

## Ownership

| Member name | Roll number | Category | Variant |
| --- | --- | --- | --- |
| Dinesh | IIT2024264 | OS command injection | In-band (command output returned) |

Course references: supplied assignment, Tables 1–2, and `Common_Web_Vulnerabilities.pptx`, slides 19–35. Complete ownership details and be ready to explain the implementation at the viva.
