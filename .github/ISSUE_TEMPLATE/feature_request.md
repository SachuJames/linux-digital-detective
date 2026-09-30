name: Feature request
description: Suggest an idea for this project
labels: [enhancement]
body:
  - type: textarea
    id: problem
    attributes:
      label: Problem
      description: What investigation task is hard or impossible today?
    validations:
      required: true
  - type: textarea
    id: proposal
    attributes:
      label: Proposal
      description: What should the tool do? New parser, rule, output format, or option?
    validations:
      required: true
  - type: textarea
    id: language
    attributes:
      label: Finding language
      description: If this adds a rule or finding, draft the cautious wording it should use (observations and leads, never verdicts).
