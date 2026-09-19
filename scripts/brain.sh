#!/usr/bin/env bash
# Control the EC2 brain's worker service over SSM (no SSH, no keys).
#
#   scripts/brain.sh status     # service state, last journal lines, busy/idle
#   scripts/brain.sh stop       # pause the EC2 brain (e.g. while recording with the faster laptop)
#   scripts/brain.sh start
#   scripts/brain.sh update     # pull main now; restarts the worker only when it is idle
set -euo pipefail
source "$(dirname "$0")/lib.sh"
require_cmd aws python

action="${1:-status}"
iid="$(stack_output BrainInstanceId)"
case "$action" in
  status) cmd='systemctl is-active ollama leash-worker; journalctl -u leash-worker -n 5 --no-pager | cut -c60-240; if [ -e /run/leash-worker.busy ]; then echo "busy: answering right now"; else echo idle; fi' ;;
  stop) cmd='systemctl stop leash-worker && echo stopped' ;;
  start) cmd='systemctl start leash-worker && sleep 2 && systemctl is-active leash-worker' ;;
  update) cmd='/usr/local/bin/leash-update; cd /opt/leash && git log --oneline -1' ;;
  *) die "usage: scripts/brain.sh status|stop|start|update" ;;
esac

log "$action on $iid"
params="$(python -c 'import json, sys; print(json.dumps({"commands": [sys.argv[1]]}))' "$cmd")"
cid="$(aws ssm send-command --instance-ids "$iid" --document-name AWS-RunShellScript \
  --parameters "$params" --query 'Command.CommandId' --output text)"
for _ in $(seq 1 20); do
  sleep 3
  status="$(aws ssm get-command-invocation --command-id "$cid" --instance-id "$iid" --query Status --output text 2>/dev/null || echo Pending)"
  case "$status" in Success|Failed|Cancelled|TimedOut) break ;; esac
done
aws ssm get-command-invocation --command-id "$cid" --instance-id "$iid" \
  --query '[StandardOutputContent, StandardErrorContent]' --output text
