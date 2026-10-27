"""Frame: a deliberately vulnerable, loopback-only image export teaching lab."""
import argparse
import base64
import binascii
import ctypes
import errno
import json
import os
import pwd
from pathlib import Path
import re
import shlex
import shutil
import struct
import subprocess
import sys
import tempfile
import time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import urlopen
from uuid import uuid4

ROOT = Path(__file__).resolve().parent
MAX_IMAGE = 3 * 1024 * 1024
MAX_BODY = MAX_IMAGE * 4 // 3 + 8192
EXPORT_NAME = re.compile(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}\.png', re.ASCII)
RESULT_PATH = re.compile(r'/results/([a-f0-9]{32})/preview\.png')
PROOF_PATH = re.compile(r'/results/([a-f0-9]{32})/proof\.txt')
REVISION = 'shell-demos-v2'


def no_new_privileges():
    """CONTAINMENT: prevent this Linux process and its children gaining rights.

    This cannot remove command injection or revoke existing filesystem access.
    PR_SET_NO_NEW_PRIVS is inherited by converter/shell children, and prevents
    set-user-ID executables/file capabilities from granting extra privileges.
    """
    if sys.platform.startswith('linux'):
        libc = ctypes.CDLL(None, use_errno=True)
        libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
        libc.prctl.restype = ctypes.c_int
        if libc.prctl(38, 1, 0, 0, 0) != 0:  # Linux PR_SET_NO_NEW_PRIVS
            raise OSError(ctypes.get_errno(), 'Could not enable no-new-privileges')


def runtime_status(server):
    """Report the local account's actual permissions for the demonstration."""
    try:
        entries = dict(line.split(':', 1) for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
    except OSError:
        entries = {}
    uid, gid = os.geteuid(), os.getegid()
    writable = os.access(ROOT, os.W_OK)
    nnp = entries.get('NoNewPrivs', '').strip() == '1'
    capabilities = entries.get('CapEff', '').strip()
    return {
        'user': pwd.getpwuid(uid).pw_name, 'uid': uid, 'gid': gid,
        'is_root': uid == 0, 'no_new_privs': nnp,
        'profile': 'desktop', 'profile_label': 'Local account (not isolated)',
        'protected_directory': str(server.protected),
        'protected_writable': os.access(server.protected, os.W_OK),
        'app_writable': writable, 'read_only_app': not writable,
        'capabilities_effective': capabilities,
    }


def png_size(path):
    """Read actual export dimensions, without an additional Python dependency."""
    with path.open('rb') as image:
        header = image.read(24)
    if len(header) != 24 or header[:8] != b'\x89PNG\r\n\x1a\n':
        raise ValueError('The processor did not produce a PNG image.')
    return struct.unpack('>II', header[16:24])


class Handler(SimpleHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/api/health':
            self.respond(200, {'app': 'frame', 'ready': True, 'processor': 'ImageMagick', 'revision': REVISION})
            return
        if self.path == '/api/runtime':
            self.respond(200, runtime_status(self.server))
            return
        proof = PROOF_PATH.fullmatch(self.path)
        if proof:
            proof_file = self.server.results / proof[1] / 'proof.txt'
            if not proof_file.is_file() or proof_file.is_symlink():
                self.send_error(404)
                return
            with proof_file.open('rb') as source:
                self.send_bytes(source.read(4096), 'text/plain; charset=utf-8')
            return
        result = RESULT_PATH.fullmatch(self.path)
        if result:
            self.send_image(self.server.results / result[1] / 'preview.png')
            return
        # NOT A SHELL SINK: these fixed static routes do not execute user input.
        # They avoid exposing application source or arbitrary host files.
        if self.path.split('?')[0] not in ('/', '/index.html', '/assets/sample.png'):
            self.send_error(404)
            return
        super().do_GET()

    def do_POST(self):
        if self.path not in ('/api/vulnerable', '/api/secure'):
            self.send_error(404)
            return
        port = self.server.server_port
        if self.headers.get('Origin') not in (
            None, f'http://127.0.0.1:{port}', f'http://localhost:{port}'
        ):
            self.send_error(403)
            return
        # SHARED VALIDATION (not the injection sink): bound request size and
        # allow-list dimensions/effects before they enter ImageMagick arguments.
        # Both endpoints validate these fields. The intentional difference is
        # the export filename's validation and execution through a shell.
        try:
            length = int(self.headers.get('Content-Length', 0))
            if not 0 < length <= MAX_BODY:
                self.respond(413, {'output': 'Choose a PNG or JPEG image up to 3 MiB.', 'status': 'Invalid input'})
                return
            body = json.loads(self.rfile.read(length))
            filename = body['filename']
            width = body.get('width', 480)
            effect = body.get('effect', 'color')
            if not isinstance(filename, str) or not 0 < len(filename) <= 120:
                raise ValueError('Enter an export filename of 1–120 characters.')
            if type(width) is not int or width not in (320, 480, 720):
                raise ValueError('Choose an export width of 320, 480, or 720 pixels.')
            if effect not in ('color', 'grayscale'):
                raise ValueError('Choose color or grayscale processing.')
            source = body.get('image')
            image_data = None
            extension = '.png'
            if source is not None:
                if not isinstance(source, str):
                    raise ValueError('Choose a PNG or JPEG image.')
                kind, encoded = source.split(',', 1)
                if kind not in ('data:image/png;base64', 'data:image/jpeg;base64'):
                    raise ValueError('Choose a PNG or JPEG image.')
                image_data = base64.b64decode(encoded, validate=True)
                if not 0 < len(image_data) <= MAX_IMAGE:
                    raise ValueError('Choose an image up to 3 MiB.')
                if kind == 'data:image/png;base64' and image_data.startswith(b'\x89PNG\r\n\x1a\n'):
                    extension = '.png'
                elif kind == 'data:image/jpeg;base64' and image_data.startswith(b'\xff\xd8\xff'):
                    extension = '.jpg'
                else:
                    raise ValueError('The file does not match its PNG or JPEG type.')
        except (ValueError, KeyError, TypeError, AttributeError, binascii.Error) as exc:
            message = str(exc) if isinstance(exc, ValueError) else 'Invalid image export request.'
            self.respond(400, {'output': message or 'Invalid image export request.', 'status': 'Invalid input'})
            return

        started = time.monotonic()
        secure = self.path == '/api/secure'
        if secure and not EXPORT_NAME.fullmatch(filename):
            # SECURED: reject paths, options, and shell syntax in PNG basenames.
            # This is an allow-list, not an incomplete blacklist of separators.
            self.respond(400, {
                'output': 'Rejected: use a simple PNG filename such as postcard.png. '
                          'Allowed: letters, numbers, underscores, and hyphens; start with a letter or number. '
                          'No process was started.',
                'status': 'Blocked', 'command': 'Not executed · filename allow-list',
                'image_url': None, 'proof': None, 'elapsed': 0,
            })
            return

        job_id = uuid4().hex
        job = self.server.results / job_id
        output_dir = job / 'exports'
        output_dir.mkdir(parents=True)
        input_path = job / ('input' + extension)
        if image_data is None:
            shutil.copyfile(ROOT / 'assets' / 'sample.png', input_path)
        else:
            input_path.write_bytes(image_data)

        # NOT THE INJECTION SINK: paths are server-generated and parameters are
        # fixed/allow-listed on both paths. Only the
        # user-controlled export filename differs in how it reaches the program.
        args = [self.server.processor, '-limit', 'memory', '128MiB',
                '-limit', 'map', '256MiB', '-limit', 'disk', '256MiB',
                str(input_path), '-resize', f'{width}x']
        if effect == 'grayscale':
            args += ['-colorspace', 'Gray']
        args += ['-strip']

        # CONTAINMENT / ENVIRONMENT HYGIENE: do not pass desktop credentials or
        # unrelated environment variables to converters or injected commands.
        # The writable request directory is also the child process's cwd/HOME.
        # These limits do not prevent an injected command using existing rights.
        child_environment = {
            'PATH': os.defpath, 'LANG': 'C.UTF-8', 'HOME': str(job),
            'TMPDIR': str(job), 'FRAME_JOB_DIR': str(job),
            'FRAME_PROTECTED': str(self.server.protected),
        }
        payload = {'image_url': None, 'proof': None}
        try:
            if secure:
                # ===== SECURED EXECUTION: COMMAND-INJECTION MITIGATION =====
                # The executable is fixed and the validated filename occupies
                # one argument. No shell parses ; | && $() or backticks.
                command = args + [str(output_dir / filename)]
                result = subprocess.run(
                    command, shell=False, capture_output=True, text=True,
                    errors='replace', timeout=5, cwd=job, env=child_environment,
                )
            else:
                # ===== INTENTIONALLY VULNERABLE CODE: DO NOT REUSE =====
                # shlex.join protects the fixed arguments, BUT the final raw
                # filename is concatenated without quoting or validation.
                # Example: postcard.png; id -> image export, then `id`.
                # shell=True is the execution sink that interprets the input.
                command = shlex.join(args) + ' ' + shlex.quote(str(output_dir)) + '/' + filename
                result = subprocess.run(
                    command, shell=True, capture_output=True, text=True,
                    errors='replace', timeout=5, cwd=job, env=child_environment,
                )
            output = result.stdout + result.stderr
            payload.update(status='Completed' if result.returncode == 0 else 'Command failed',
                           returncode=result.returncode, output=output or '(No process output)')
            exports = sorted(p for p in output_dir.glob('*.png') if p.is_file() and not p.is_symlink())
            if exports:
                preview = job / 'preview.png'
                shutil.copyfile(exports[0], preview)
                actual_width, actual_height = png_size(preview)
                payload.update(image_url=f'/results/{job_id}/preview.png',
                               width=actual_width, height=actual_height,
                               output=f'Exported {actual_width} × {actual_height} PNG.\n'
                                      f'Filename: {exports[0].name}\n\n'
                                      f'Process stdout / stderr:\n{output or "(No process output)"}')
        except subprocess.TimeoutExpired:
            payload.update(output='Image export exceeded the 5-second lab timeout.', status='Timed out')
        except (OSError, ValueError) as exc:
            payload.update(output=str(exc), status='Execution error')
        # EVIDENCE, NOT SIMULATION: the RCE marker is displayed only if an
        # injected command actually created this file. The application does not
        # write the proof itself. No host configuration or user files involved.
        proof = job / 'proof.txt'
        if proof.is_file() and not proof.is_symlink():
            with proof.open('rb') as source:
                proof_text = source.read(4096).decode('utf-8', errors='replace')
            payload['proof'] = {
                'text': proof_text,
                'url': f'/results/{job_id}/proof.txt',
            }
        payload.update(
            command=command, elapsed=round((time.monotonic() - started) * 1000),
            containment={
                'mode': 'local-permissions',
                'protected_write_blocked': not os.access(self.server.protected, os.W_OK),
                'note': 'The protected-write result is in process stderr. '
                        'Local fixture uses directory permissions only. Its owner could change them; this is not isolation.',
            },
        )
        self.respond(200, payload)

    def send_image(self, path):
        try:
            data = path.read_bytes()
        except FileNotFoundError:
            self.send_error(404)
            return
        self.send_bytes(data, 'image/png')

    def send_bytes(self, data, content_type):
        self.send_response(200)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(data)

    def respond(self, code, data):
        # NOT A COMMAND EXECUTION SINK: JSON serialization sends data to the
        # browser. The frontend uses textContent, so output is not parsed as HTML.
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run Frame, the local image export teaching lab.')
    parser.add_argument('--port', type=int, default=8000, help='Local port (default: 8000)')
    options = parser.parse_args()
    if not 1 <= options.port <= 65535:
        parser.error('--port must be between 1 and 65535')
    if os.geteuid() == 0:
        parser.exit(1, 'Run Frame as a non-root user.\n')
    # LEAST PRIVILEGE / CONTAINMENT, process-wide (both demonstration paths):
    # refuse root, make temporary files private, and prevent child privilege
    # elevation. A desktop account still has its normal filesystem access.
    os.umask(0o077)
    try:
        no_new_privileges()
    except OSError as exc:
        parser.exit(1, f'Could not apply runtime containment: {exc}\n')
    processor = shutil.which('magick') or shutil.which('convert')
    if processor is None:
        parser.exit(1, 'ImageMagick is missing. Install ImageMagick (magick or convert), then run again.\n')
    os.chdir(ROOT)
    url = f'http://127.0.0.1:{options.port}'
    try:
        server = ThreadingHTTPServer(('127.0.0.1', options.port), Handler)
    except OSError as exc:
        if exc.errno != errno.EADDRINUSE:
            parser.exit(1, f'Could not start Frame: {exc}\n')
        try:
            with urlopen(url + '/api/health', timeout=1) as response:
                health = json.load(response)
                app = health.get('app')
        except (OSError, ValueError, AttributeError):
            app = None
        if app == 'frame':
            if health.get('revision') != REVISION:
                parser.exit(1, 'An older Frame server is running. Stop it with Ctrl+C, then restart python3 server.py.\n')
            parser.exit(0, f'Frame is already running. Open {url} in your browser.\n')
        if app == 'netcheck':
            parser.exit(1, 'The old Netcheck server is still running. Press Ctrl+C in its terminal, '
                           'then run python3 server.py again.\n')
        parser.exit(1, f'Port {options.port} is already in use. Choose another port: '
                       'python3 server.py --port 8001\n')
    server.processor = processor
    print(f'Frame image lab: {url}\nKeep this terminal open; Ctrl+C stops the server.', flush=True)
    try:
        with tempfile.TemporaryDirectory(prefix='frame-lab-') as results:
            server.results = Path(results)
            # LOCAL PERMISSIONS FIXTURE: deliberately contains no secrets.
            # With a non-root account, mode 0555 denies a normal file write.
            # The same account owns it and could chmod it, so this fixture
            # demonstrates permissions; it does not isolate the process.
            server.protected = server.results / 'protected'
            server.protected.mkdir()
            (server.protected / 'note.txt').write_text('Teaching fixture: exports belong in the request directory.\n')
            (server.protected / 'note.txt').chmod(0o444)
            server.protected.chmod(0o555)
            try:
                server.serve_forever()
            finally:
                server.protected.chmod(0o755)
    except KeyboardInterrupt:
        print('\nFrame stopped.')
    finally:
        server.server_close()
