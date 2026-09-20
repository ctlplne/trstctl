#!/bin/sh
# SPDX-License-Identifier: BUSL-1.1
#
# Tear the partner lab down completely and prove it is gone.
#
# `docker compose --profile partner-lab stop` is NOT a teardown: a profile-filtered
# stop skips services outside the profile (the control plane itself), which keeps
# 9443 and 10443-10449 bound and breaks the next bring-up (OPP-C04). This script
# owns the full teardown for exactly one Compose project — containers, named
# volumes, and the project network — and exits non-zero if anything of that
# project survives, so a half-torn lab is a visible failure, never a silent one.
#
# Usage: deploy/demo/lab/down.sh            (project TRSTCTL_LAB_PROJECT, default trstctl-partner-lab)
#        TRSTCTL_LAB_PROJECT=clsr-g289-lab deploy/demo/lab/down.sh
set -u
lab_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
repo_dir="$(CDPATH= cd -- "$lab_dir/../../.." && pwd)"
lab_project="${TRSTCTL_LAB_PROJECT:-trstctl-partner-lab}"
case "$lab_project" in
  ""|[!a-z0-9]*|*[!a-z0-9_-]*)
    printf '%s\n' "TRSTCTL_LAB_PROJECT must start with a lowercase letter or digit and contain only lowercase letters, digits, underscores, and hyphens." >&2
    exit 2
    ;;
esac
cd "$repo_dir" || exit 1
compose="docker compose -p $lab_project -f deploy/demo/docker-compose.yml -f deploy/demo/lab/docker-compose.yml"
# Every profile, so out-of-profile services (the control plane) are torn down too.
$compose --profile partner-lab --profile partner-lab-customer down --volumes --remove-orphans || exit $?
# Belt and braces: anything still labelled or named for this project is removed.
leftover_containers=$(docker ps -aq --filter "label=com.docker.compose.project=$lab_project" --filter "name=^${lab_project}-" | sort -u)
if [ -n "$leftover_containers" ]; then docker rm -f $leftover_containers >/dev/null || exit $?; fi
leftover_volumes=$(docker volume ls -q --filter "label=com.docker.compose.project=$lab_project")
if [ -n "$leftover_volumes" ]; then docker volume rm $leftover_volumes >/dev/null || exit $?; fi
docker network rm "${lab_project}_default" >/dev/null 2>&1 || true
# Prove it: zero containers, volumes, and networks for this project remain.
remaining_containers=$(docker ps -aq --filter "label=com.docker.compose.project=$lab_project" | wc -l | tr -d ' ')
remaining_volumes=$(docker volume ls -q --filter "label=com.docker.compose.project=$lab_project" | wc -l | tr -d ' ')
remaining_networks=$(docker network ls -q --filter "label=com.docker.compose.project=$lab_project" | wc -l | tr -d ' ')
printf '%s\n' "Partner lab $lab_project torn down: containers=$remaining_containers volumes=$remaining_volumes networks=$remaining_networks"
if [ "$remaining_containers" != 0 ] || [ "$remaining_volumes" != 0 ] || [ "$remaining_networks" != 0 ]; then
  printf '%s\n' "Teardown incomplete for $lab_project; the next bring-up would collide on its ports." >&2
  exit 1
fi
