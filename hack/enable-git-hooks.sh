#!/usr/bin/env bash

# enable git commit hooks

LOCAL_REPO="$(git rev-parse --show-toplevel)"
if [[ -d ${LOCAL_REPO}/.git-hooks/ ]]; then
  git config core.hooksPath "${LOCAL_REPO}/.git-hooks/" > /dev/null
fi
