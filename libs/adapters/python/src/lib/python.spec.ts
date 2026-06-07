import { pythonSourceAdapter } from './python';

describe('pythonSourceAdapter', () => {
  it('analyzes valid Python source', () => {
    const result = pythonSourceAdapter.analyze(
      'app.py',
      [
        'def main():',
        '    print("ok")',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.language).toBe('python');
    expect(result.data.nodes).toHaveLength(1);
  });

  it('reports malformed Python source', () => {
    const result = pythonSourceAdapter.analyze(
      'broken.py',
      [
        'def main(',
        '    print("oops")',
      ].join('\n'),
    );

    expect(result.success).toBe(false);
  });

  it('emits phase-1 security facts', () => {
    const result = pythonSourceAdapter.analyze(
      'app.py',
      [
        'import json',
        'import logging',
        'import pickle',
        'import subprocess',
        '',
        'logger = logging.getLogger(__name__)',
        'API_SECRET = "sk_live_12345678"',
        '',
        '@app.get("/reports/<path:report_name>")',
        'def get_report(report_name: str):',
        '    target = REPORT_ROOT / report_name',
        '    logger.info("email=%s token=%s", report_name, request.headers.get("Authorization"))',
        '    subprocess.run(report_name, shell=True)',
        '    query = f"SELECT * FROM reports WHERE name = \'{report_name}\'"',
        '    cursor.execute(query)',
        '    payload = request.data',
        '    config = pickle.loads(payload)',
        '    return target.read_text(encoding="utf-8")',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.semantics?.controlFlow?.facts.map((fact) => fact.kind)).toEqual([
      'security.hardcoded-credentials',
      'python.security.path-traversal-user-input',
      'security.sensitive-data-in-logs-and-telemetry',
      'python.security.subprocess-shell-enabled',
      'security.command-execution-with-request-input',
      'security.sql-interpolation',
      'security.unsafe-deserialization',
      'security.request-path-file-read',
    ]);
  });

  it('emits transport and crypto security facts', () => {
    const result = pythonSourceAdapter.analyze(
      'transport.py',
      [
        'import hashlib',
        'import requests',
        'import ssl',
        '',
        'def sign_session(payload: bytes, secret: bytes):',
        '    requests.get("http://api.example.com/users")',
        '    requests.get("https://api.example.com/users", verify=False)',
        '    digest = hashlib.sha1(payload + secret).hexdigest()',
        '    context = ssl._create_unverified_context()',
        '    return digest, context',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.semantics?.controlFlow?.facts.map((fact) => fact.kind)).toEqual([
      'security.insecure-http-transport',
      'security.tls-verification-disabled',
      'security.weak-hash-algorithm',
      'security.tls-verification-disabled',
    ]);
  });

  it('emits Django unsafe production settings facts', () => {
    const result = pythonSourceAdapter.analyze(
      'production_settings.py',
      [
        'DEBUG = True',
        'ALLOWED_HOSTS = ["*"]',
        'SESSION_COOKIE_SECURE = False',
        'CSRF_COOKIE_SECURE = False',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(
      result.data.semantics?.controlFlow?.facts.filter(
        (fact) => fact.kind === 'python.security.django-unsafe-production-settings',
      ),
    ).toHaveLength(4);
  });

  it('emits Django CSRF exemption facts when mutations touch unsafe methods', () => {
    const result = pythonSourceAdapter.analyze(
      'views.py',
      [
        '@csrf_exempt',
        'def change_email(request):',
        '    if request.method == "POST":',
        '        request.user.email = request.POST["email"]',
        '        request.user.save()',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(
      result.data.semantics?.controlFlow?.facts.some(
        (fact) => fact.kind === 'python.security.django-csrf-exempt-state-changing',
      ),
    ).toBe(true);
  });

  it('emits Django missing CSRF middleware facts', () => {
    const result = pythonSourceAdapter.analyze(
      'settings.py',
      [
        'MIDDLEWARE = [',
        '    "django.middleware.security.SecurityMiddleware",',
        ']',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(
      result.data.semantics?.controlFlow?.facts.some(
        (fact) => fact.kind === 'python.security.django-missing-csrf-middleware',
      ),
    ).toBe(true);
  });

  it('emits Django missing SecurityMiddleware facts', () => {
    const result = pythonSourceAdapter.analyze(
      'settings.py',
      [
        'MIDDLEWARE = [',
        '    "django.middleware.common.CommonMiddleware",',
        '    "django.middleware.csrf.CsrfViewMiddleware",',
        ']',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(
      result.data.semantics?.controlFlow?.facts.some(
        (fact) => fact.kind === 'python.security.django-security-middleware-missing',
      ),
    ).toBe(true);
  });

  it('emits Django mark_safe usage facts', () => {
    const result = pythonSourceAdapter.analyze(
      'views.py',
      [
        'from django.utils.safestring import mark_safe',
        '',
        'def preview(request):',
        '    return mark_safe(request.GET["q"])',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(
      result.data.semantics?.controlFlow?.facts.some(
        (fact) => fact.kind === 'python.security.django-mark-safe',
      ),
    ).toBe(true);
  });

  it('emits Django format_html unsafe interpolation facts', () => {
    const result = pythonSourceAdapter.analyze(
      'views.py',
      [
        'from django.utils.html import format_html',
        '',
        'def greet(request):',
        '    user_name = request.GET.get("name", "guest")',
        '    return format_html("<div>{}</div>", user_name)',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(
      result.data.semantics?.controlFlow?.facts.some(
        (fact) => fact.kind === 'python.security.django-format-html-unsafe',
      ),
    ).toBe(true);
  });

  it('emits DRF permissive default permission facts', () => {
    const result = pythonSourceAdapter.analyze(
      'settings.py',
      [
        'REST_FRAMEWORK = {',
        '    "DEFAULT_PERMISSION_CLASSES": [',
        '        "rest_framework.permissions.AllowAny",',
        '    ],',
        '}',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(
      result.data.semantics?.controlFlow?.facts.some(
        (fact) => fact.kind === 'python.security.drf-allow-any-default',
      ),
    ).toBe(true);
  });

  it('emits DRF AllowAny facts on unsafe methods', () => {
    const result = pythonSourceAdapter.analyze(
      'views.py',
      [
        '@api_view(["POST"])',
        '@permission_classes([AllowAny])',
        'def create_widget(request):',
        '    return Response({})',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(
      result.data.semantics?.controlFlow?.facts.some(
        (fact) => fact.kind === 'python.security.drf-allow-any-unsafe-method',
      ),
    ).toBe(true);
  });

  it('emits Flask unsafe HTML output facts', () => {
    const result = pythonSourceAdapter.analyze(
      'app.py',
      [
        '@app.route("/preview")',
        'def preview():',
        '    return Markup(request.args["html"])',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(
      result.data.semantics?.controlFlow?.facts.some(
        (fact) => fact.kind === 'python.security.flask-unsafe-html-output',
      ),
    ).toBe(true);
  });

  it('emits Flask debug enabled facts', () => {
    const result = pythonSourceAdapter.analyze(
      'app.py',
      [
        'import os',
        '',
        'app.config["DEBUG"] = True',
        'os.environ["FLASK_DEBUG"] = "1"',
        'app.run(debug=True)',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(
      result.data.semantics?.controlFlow?.facts.filter(
        (fact) => fact.kind === 'python.security.flask-debug-enabled',
      ),
    ).toHaveLength(3);
  });

  it('emits Python path traversal user-input facts', () => {
    const result = pythonSourceAdapter.analyze(
      'app.py',
      [
        'from pathlib import Path',
        'from flask import send_file',
        'import os',
        '',
        'REPORT_ROOT = Path("reports")',
        '',
        '@app.get("/reports/<path:report_name>")',
        'def get_report(report_name):',
        '    target = REPORT_ROOT / report_name',
        '    return send_file(os.path.join("/tmp", request.args["name"]))',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(
      result.data.semantics?.controlFlow?.facts.filter(
        (fact) => fact.kind === 'python.security.path-traversal-user-input',
      ),
    ).toHaveLength(3);
  });

  it('emits Flask unsafe upload filename facts', () => {
    const result = pythonSourceAdapter.analyze(
      'app.py',
      [
        '@app.post("/upload")',
        'def upload():',
        '    file = request.files["file"]',
        '    file.save(os.path.join(app.config["UPLOAD_FOLDER"], file.filename))',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(
      result.data.semantics?.controlFlow?.facts.some(
        (fact) => fact.kind === 'python.security.flask-unsafe-upload-filename',
      ),
    ).toBe(true);
  });

  it('emits Flask missing upload body limit facts', () => {
    const result = pythonSourceAdapter.analyze(
      'app.py',
      [
        '@app.post("/upload")',
        'def upload():',
        '    file = request.files["file"]',
        '    file.save(os.path.join("uploads", "blob.bin"))',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(
      result.data.semantics?.controlFlow?.facts.some(
        (fact) => fact.kind === 'python.security.flask-missing-upload-body-limit',
      ),
    ).toBe(true);
  });

  it('emits FastAPI insecure CORS facts', () => {
    const result = pythonSourceAdapter.analyze(
      'main.py',
      [
        'app.add_middleware(',
        '    CORSMiddleware,',
        '    allow_origins=["*"],',
        '    allow_credentials=True,',
        '    allow_methods=["*"],',
        '    allow_headers=["*"],',
        ')',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(
      result.data.semantics?.controlFlow?.facts.some(
        (fact) => fact.kind === 'python.security.fastapi-insecure-cors',
      ),
    ).toBe(true);
  });


  it('emits shared performance hygiene facts', () => {
    const result = pythonSourceAdapter.analyze(
      'test_service.py',
      [
        'import asyncio',
        'asyncio.gather(items.map(task))',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    expect(result.data.semantics?.controlFlow?.facts.map((fact) => fact.kind)).toContain(
      'py.performance.no-unbounded-concurrency',
    );
  });

  it('emits Python open redirect and SSRF facts', () => {
    const result = pythonSourceAdapter.analyze(
      'app.py',
      [
        'from flask import redirect',
        'import requests',
        '',
        'def login():',
        '    return redirect(request.args.get("next"))',
        '',
        'def fetch():',
        '    requests.get(request.args["url"])',
        '    requests.get("http://169.254.169.254/latest/meta-data")',
      ].join('\n'),
    );

    expect(result.success).toBe(true);

    if (!result.success) {
      throw new Error('Expected analysis success.');
    }

    const kinds = result.data.semantics?.controlFlow?.facts.map((fact) => fact.kind) ?? [];

    expect(kinds).toContain('security.open-redirect');
    expect(kinds.filter((kind) => kind === 'security.ssrf')).toHaveLength(2);
  });

  it('emits bandit security facts', () => {
    // insecure-cipher
    const r1 = pythonSourceAdapter.analyze(
      'crypto.py',
      'cipher = Crypto.Cipher.DES.new(key, Crypto.Cipher.DES.MODE_ECB)',
    );
    expect(r1.success).toBe(true);
    if (!r1.success) throw new Error('Expected analysis success.');
    const facts1 = r1.data.semantics?.controlFlow?.facts ?? [];
    expect(facts1.filter(f => f.kind === 'python.security.insecure-cipher')).not.toHaveLength(0);

    // insecure-xml-parser
    const r2 = pythonSourceAdapter.analyze(
      'parse_xml.py',
      'xml.etree.ElementTree.parse("data.xml")',
    );
    expect(r2.success).toBe(true);
    if (!r2.success) throw new Error('Expected analysis success.');
    const facts2 = r2.data.semantics?.controlFlow?.facts ?? [];
    expect(facts2.filter(f => f.kind === 'python.security.insecure-xml-parser')).not.toHaveLength(0);

    // assert-outside-test (already works)
    const r3 = pythonSourceAdapter.analyze(
      'app.py',
      'assert x > 0',
    );
    expect(r3.success).toBe(true);
    if (!r3.success) throw new Error('Expected analysis success.');
    expect(
      r3.data.semantics?.controlFlow?.facts.some(f => f.kind === 'python.correctness.assert-outside-test'),
    ).toBe(true);
  });

});
