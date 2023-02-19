{% import 'salt.runner' as runner %}
jobs:
  runner.state.orchestrate:
    - mods:
        - run_patching

