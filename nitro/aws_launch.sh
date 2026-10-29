#!/usr/bin/env bash
# Run on YOUR machine after `aws configure sso` (or an AWS_PROFILE). Creates: an IAM role for SSM, a security group with NO inbound rules, and one
# Nitro-Enclaves-enabled instance. UNTESTED (written from AWS docs; no AWS access was available). Review before running. Cost: ~USD 0.15-0.20/hour.
set -euo pipefail
REGION="${AWS_REGION:-us-east-1}"
TYPE="${INSTANCE_TYPE:-c5.xlarge}"        # must be a Nitro Enclaves-capable size (not .large, not t2/t3)
NAME="vault-enclave"
export AWS_DEFAULT_REGION="$REGION"

echo "account: $(aws sts get-caller-identity --query Account --output text)  region: $REGION  type: $TYPE"
read -r -p "Create billable resources? Type YES: " ok; [ "$ok" = "YES" ] || { echo "stopped"; exit 1; }

AMI=$(aws ssm get-parameter --name /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 --query Parameter.Value --output text)

aws iam get-role --role-name "$NAME-role" >/dev/null 2>&1 || {
  aws iam create-role --role-name "$NAME-role" --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' >/dev/null
  aws iam attach-role-policy --role-name "$NAME-role" --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore
  aws iam create-instance-profile --instance-profile-name "$NAME-profile" >/dev/null
  aws iam add-role-to-instance-profile --instance-profile-name "$NAME-profile" --role-name "$NAME-role"
  sleep 12                                  # IAM is eventually consistent
}

VPC=$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)
SG=$(aws ec2 describe-security-groups --filters Name=group-name,Values="$NAME-sg" Name=vpc-id,Values="$VPC" --query 'SecurityGroups[0].GroupId' --output text)
if [ "$SG" = "None" ]; then
  SG=$(aws ec2 create-security-group --group-name "$NAME-sg" --description "vault enclave: no inbound" --vpc-id "$VPC" --query GroupId --output text)
fi

ID=$(aws ec2 run-instances --image-id "$AMI" --instance-type "$TYPE" --enclave-options Enabled=true \
  --iam-instance-profile Name="$NAME-profile" --security-group-ids "$SG" \
  --metadata-options HttpTokens=required,HttpEndpoint=enabled \
  --block-device-mappings 'DeviceName=/dev/xvda,Ebs={VolumeSize=20,VolumeType=gp3,Encrypted=true}' \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME}]" --query 'Instances[0].InstanceId' --output text)
echo "$ID" > "$(dirname "$0")/.instance_id"
echo "launched $ID. No inbound ports are open: connect with SSM:  aws ssm start-session --target $ID"
echo "REMEMBER: run nitro/aws_teardown.sh when finished (billing continues while it runs)."
