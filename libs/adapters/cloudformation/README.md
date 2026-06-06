# @critiq/adapter-cloudformation

OSS CloudFormation adapter for `critiq check`.

## Behavior

- Detects AWS CloudFormation and SAM templates in `.yaml`, `.yml`, and `.json`
  files using `AWSTemplateFormatVersion`, top-level `Resources`, or
  `Transform: AWS::Serverless`.
- Runs `cfn-lint -f json <file>` and normalizes matches into observed facts
  with kind `cfn.lint.finding`.
- Preserves cfn-lint rule ids (`E1020`, `W2001`, `I1002`, etc.) in fact
  metadata as `ruleId`.
- Emits a warning diagnostic when `cfn-lint` is not installed instead of
  failing the scan.

## Public API

- `analyzeCloudFormationFile(path, text, options?)`
- `cloudformationSourceAdapter`
