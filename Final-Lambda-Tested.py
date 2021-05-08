import json
import boto3

# This lambda function is used to revoke security group ingress rules based on cloudwatch event "AuthorizeSecurityGroupIngress" when the Security Group allows SSH to world.

def lambda_handler(event, context):
    # event = {"version":"0","id":"7c5b223c-1517-4e97-c853-89497afaf3b2","detail-type":"AWS API Call via CloudTrail","source":"aws.ec2","account":"963584523464","time":"2021-05-07T17:42:22Z","region":"us-east-1","resources":[],"detail":{"eventVersion":"1.08","userIdentity":{"type":"Root","principalId":"963584523464","arn":"arn:aws:iam::963584523464:root","accountId":"963584523464","accessKeyId":"ASIA6AWQ47TEKUBOLMOH","sessionContext":{"sessionIssuer":{},"webIdFederationData":{},"attributes":{"mfaAuthenticated":"True","creationDate":"2021-05-07T17:31:52Z"}}},"eventTime":"2021-05-07T17:42:22Z","eventSource":"ec2.amazonaws.com","eventName":"AuthorizeSecurityGroupIngress","awsRegion":"us-east-1","sourceIPAddress":"165.225.243.77","userAgent":"console.ec2.amazonaws.com","requestParameters":{"groupId":"sg-0db7d4784c4db8612","ipPermissions":{"items":[{"ipProtocol":"tcp","fromPort":22,"toPort":22,"groups":{},"ipRanges":{"items":[{"cidrIp":"0.0.0.0/0"}]},"ipv6Ranges":{"items":[{"cidrIpv6":"::/0"}]},"prefixListIds":{}}]}},"responseElements":{"requestId":"dae02e73-e4c0-4318-b131-a7daa762ab1b","_return":True},"requestID":"dae02e73-e4c0-4318-b131-a7daa762ab1b","eventID":"7718d386-c058-4b0a-b6b7-6ffa2870aeaf","readOnly":False,"eventType":"AwsApiCall","managementEvent":True,"eventCategory":"Management"}}

    # Get value of variables from event
    event_region = event["detail"]["awsRegion"]
    event_sgid = event["detail"]["requestParameters"]["groupId"]
    event_rules = event["detail"]["requestParameters"]["ipPermissions"]["items"]

    # Create a EC2 client object
    ec2_client = boto3.client(service_name="ec2", region_name=event_region)

    # Check for condition in SG and revoke SG if True
    response = ec2_client.describe_security_groups(GroupIds=[event_sgid])
    security_groups = response.get("SecurityGroups")
    for sg in security_groups:
        for each_rule in sg.get("IpPermissions"):
            if each_rule.get("FromPort") == 22:
                try:
                    sg_name = sg["GroupName"]
                    ip_perm = sg["IpPermissions"]
                    sg_id = sg["GroupId"]
                    print(sg_id)
                    # Use EC2 client object with revoke_security_group_ingress method to revoke offending rules
                    ec2_client.revoke_security_group_ingress(GroupName=sg_name, IpPermissions=ip_perm)
                    print("Security Group Ingress Revoked for {}".format(sg_name))
                    # Create Tags to mark the resource and alert the owner
                    ec2_client.create_tags(
                        DryRun=False,
                        Resources=[
                            sg_id
                        ],
                        Tags=[
                            {
                                'Key': 'SecurityAlert',
                                'Value': 'Rule was modified as it had insecure settings'
                            },
                        ]
                    )
                except Exception as e:
                    print(e)
            else:
                print("No Insecure Rule found in {}".format(event_sgid))

