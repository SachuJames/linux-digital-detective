name: Bug report
description: Report a reproducible problem
labels: [bug]
body:
  - type: textarea
    id: what
    attributes:
      label: What happened?
      description: What you saw, and what you expected instead.
    validations:
      required: true
  - type: textarea
    id: repro
    attributes:
      label: Reproduction
      description: Command line and a minimal (synthetic, anonymized) log snippet that reproduces it. Do not paste real logs with personal data.
    validations:
      required: true
  - type: input
    id: version
    attributes:
      label: Version
      description: Output of `lddetective version`.
    validations:
      required: true
