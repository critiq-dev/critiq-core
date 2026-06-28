import {
  collectPythonCorrectnessFacts,
  PYTHON_CORRECTNESS_FACT_KINDS,
} from './python-correctness';

describe('python-correctness collectors', () => {
  it('flags bare except handlers', () => {
    const facts = collectPythonCorrectnessFacts({
      detector: 'python-detector',
      text: [
        'try:',
        '    run()',
        'except:',
        '    pass',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PYTHON_CORRECTNESS_FACT_KINDS.bareExcept,
    );
  });

  it('flags mutable defaults in function signatures', () => {
    const facts = collectPythonCorrectnessFacts({
      detector: 'python-detector',
      text: [
        'def build(values=[], options={}, labels=set()):',
        '    return values',
      ].join('\n'),
    });

    expect(facts.filter((fact) => fact.kind === PYTHON_CORRECTNESS_FACT_KINDS.dangerousMutableDefault)).toHaveLength(1);
  });

  it('flags broad exception handlers for Exception and BaseException', () => {
    const facts = collectPythonCorrectnessFacts({
      detector: 'python-detector',
      text: [
        'try:',
        '    risky()',
        'except Exception:',
        '    recover()',
        'try:',
        '    risky_again()',
        'except BaseException as exc:',
        '    log(exc)',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === PYTHON_CORRECTNESS_FACT_KINDS.broadExceptionHandler,
      ),
    ).toHaveLength(2);
  });

  it('flags tuple-form broad exception handlers containing Exception or BaseException', () => {
    const facts = collectPythonCorrectnessFacts({
      detector: 'python-detector',
      text: [
        'try:',
        '    run()',
        'except (ValueError, Exception) as e:',
        '    log(e)',
        'try:',
        '    run2()',
        'except (BaseException,):',
        '    pass',
        'try:',
        '    run3()',
        'except (EOFError, pickle.UnpicklingError, Exception):',
        '    pass',
      ].join('\n'),
    });

    expect(
      facts.filter(
        (fact) =>
          fact.kind === PYTHON_CORRECTNESS_FACT_KINDS.broadExceptionHandler,
      ),
    ).toHaveLength(3);
  });

  it('flags duplicate keys in dict literals', () => {
    const facts = collectPythonCorrectnessFacts({
      detector: 'python-detector',
      text: [
        'settings = {',
        "  'mode': 'safe',",
        "  'mode': 'fast',",
        '}',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PYTHON_CORRECTNESS_FACT_KINDS.duplicateDictKey,
    );
  });

  it('flags assert on tuple expressions', () => {
    const facts = collectPythonCorrectnessFacts({
      detector: 'python-detector',
      text: [
        'def test_value(x, y):',
        '    assert (x, y)',
      ].join('\n'),
    });

    expect(facts.map((fact) => fact.kind)).toContain(
      PYTHON_CORRECTNESS_FACT_KINDS.assertOnTuple,
    );
  });

  it('does not flag safe patterns', () => {
    const facts = collectPythonCorrectnessFacts({
      detector: 'python-detector',
      text: [
        'def load(value=None):',
        '    if value is None:',
        '        value = []',
        '    return value',
        'try:',
        '    run()',
        'except ValueError:',
        '    pass',
        'try:',
        '    run2()',
        'except (ValueError, TypeError):',
        '    pass',
        'try:',
        '    run3()',
        'except (OSError,) as e:',
        '    log(e)',
        "payload = {'x': 1, 'y': 2}",
        'assert value',
      ].join('\n'),
    });

    expect(facts).toHaveLength(0);
  });
});
