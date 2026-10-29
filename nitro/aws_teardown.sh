#!/usr/bin/env bash
# Terminates the instance and removes what aws_launch.sh created. UNTESTED. Run it when you are done: billing continues until then.
set -uo pipefail
REGION="${AWS_REGION:-us-east-1}"; export AWS_DEFAULT_REGION="$REGION"; NAME="vault-enclave"
ID=$(cat "$(dirname "$0")/.instance_id" 2>/dev/null || aws ec2 describe-instances --filters Name=tag:Name,Values=$NAME Name=instance-state-name,Values=running,pending,stopped --query 'Reservations[0].Instances[0].InstanceId' --output text)
[ -n "$ID" ] && [ "$ID" != "None" ] && { aws ec2 terminate-instances --instance-ids "$ID" >/dev/null && echo "terminating $ID"; aws ec2 wait instance-terminated --instance-ids "$ID"; }
SG=$(aws ec2 describe-security-groups --filters Name=group-name,Values="$NAME-sg" --query 'SecurityGroups[0].GroupId' --output text)
[ "$SG" != "None" ] && aws ec2 delete-security-group --group-id "$SG" && echo "deleted security group"
aws iam remove-role-from-instance-profile --instance-profile-name "$NAME-profile" --role-name "$NAME-role" 2>/dev/null
aws iam delete-instance-profile --instance-profile-name "$NAME-profile" 2>/dev/null
aws iam detach-role-policy --role-name "$NAME-role" --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore 2>/dev/null
aws iam delete-role --role-name "$NAME-role" 2>/dev/null && echo "deleted role"
rm -f "$(dirname "$0")/.instance_id"; echo "done. Also delete any KMS key you created (schedule deletion, minimum 7 days)."
