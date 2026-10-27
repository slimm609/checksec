#!/usr/bin/env bash

# enable git commit hooks

# core.hooksPath lives in the config shared by all linked worktrees, so always point it at the main worktree's hooks
# (not at the current worktree, which may be deleted later), derived from the common git dir.
GIT_COMMON_DIR="$(git rev-parse --path-format=absolute --git-common-dir)"
if [[ ${GIT_COMMON_DIR##*/} == .git ]]; then
  LOCAL_REPO="${GIT_COMMON_DIR%/.git}"
else
  LOCAL_REPO="$(git rev-parse --show-toplevel)"
fi
if [[ -d ${LOCAL_REPO}/.git-hooks/ ]]; then
  git config core.hooksPath "${LOCAL_REPO}/.git-hooks/" > /dev/null
fi
