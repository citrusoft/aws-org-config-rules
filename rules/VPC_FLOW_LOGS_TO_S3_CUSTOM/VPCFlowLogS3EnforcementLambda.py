#
# Custom AWS Config Rule - VPC Flow Logs
#

import boto3, json

def evaluate_compliance(config_item, r_id, creds):
    """
    Assuming the given role-credentials...
    Evaluates the VPC FlowLog compliance of the given resource id.
    It's assumed the given resource id is a VPC.
    Returns COMPLIANT if VPC FlowLogging correct.
    Returns NON_COMPLIANT if VPC lowLogging incorrect and could not be corrected.
    Otherwise, returns IT_BROKE.
    """
    if (config_item['resourceType'] != 'AWS::EC2::VPC'):
        return 'NOT_APPLICABLE'
    ec2 = boto3.client('ec2',
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken'],
    )
    if is_flow_logs_enabled(r_id, ec2):
        return 'COMPLIANT'
    elif create_flow_logs(r_id, ec2):
        return 'NON_COMPLIANT'
    else:
        return 'IT_BROKE'

def is_flow_logs_enabled(vpc_id, ec2):
    """
    Detects if the given VPC is FlowLogging into centralized S3 bucket.
    Returns TRUE if LogDestination correct, otherwise, returns FALSE.
    """
    response = ec2.describe_flow_logs(
        Filter=[
            {
                'Name': 'resource-id',
                'Values': [
                    vpc_id,
                ],
            },
            {
                'Name': 'log-destination-type',
                'Values': [
                    's3'
                ],
            },
        ],
    )
    if len(response[u'FlowLogs']) > 0: 
        for i in response[u'FlowLogs']:
            if i[u'LogDestination'] == 'arn:aws:s3:::pge-central-flowlogs':
                return True
    return False

def create_flow_logs(vpc_id, ec2):
    """
    Configures the given VPC to FlowLog into centralized S3 bucket.
    Returns FALSE wth unsuccessful response, otherwise, returns TRUE.
    """
    response = ec2.create_flow_logs(
        ResourceIds=[
            vpc_id
        ],
        ResourceType='VPC',
        TrafficType='ALL',
        LogDestinationType='s3',
        LogDestination='arn:aws:s3:::pge-central-flowlogs'
    )
    return not bool(response[u'Unsuccessful'])

def assume_role(role_to_assume_arn,role_session_name='vpcflowlog2S3session'):
    """
    Fetches sts credentials for the given role arn.
    Optionally, client can name the boto3 session.
    Returns sts credentials.
    """
    print "assume_role("+role_to_assume_arn+','+role_session_name+')'
    # Create IAM client
    sts_default_provider_chain = boto3.client('sts')

    print('Default Provider Identity: : ' + sts_default_provider_chain.get_caller_identity()['Arn'])

    response=sts_default_provider_chain.assume_role(
        RoleArn=role_to_assume_arn,
        RoleSessionName=role_session_name
    )

    creds=response['Credentials']
    # Test the credentials
    sts_assumed_role = boto3.client('sts',
        aws_access_key_id=creds['AccessKeyId'],
        aws_secret_access_key=creds['SecretAccessKey'],
        aws_session_token=creds['SessionToken'],
    )
    print('AssumedRole Identity: ' + sts_assumed_role.get_caller_identity()['Arn'])
    return creds


def lambda_handler(event, context):
    """
    The infamous entry point to this function, lambda_handler.
    This funk is intended to run from a centralized account.
    This funk assumes executionRole to evaluate VPC FlowLog configuration compliance.
    It puts evaluation into configservice of the given evaluationRole.
    :param event:    Assumes triggering event to be a dict, ConfigurationItemChangeNotification.
    :param context:  AWS Lambda uses this parameter to provide runtime information.
    :return:         nothing.
    """
    print(event)
    invoking_event = json.loads(event['invokingEvent'])
    compliance_value = 'NOT_APPLICABLE'
    account_id = json.loads(event['accountId'])
    resource_id = invoking_event['configurationItem']['resourceId']
    print "resource id="+resource_id                
    ruleParameters = json.loads(event['ruleParameters'])
    # Assume the role passed from the managed-account
    executionCredentials = assume_role('arn:aws:iam::'+account_id+':role/VPCFlowLogS3EnforcementLambdaRole2')
    compliance_value = evaluate_compliance(invoking_event['configurationItem'], resource_id, executionCredentials)
    print "compliance-result="+compliance_value
    # Assume the role passed from the managed-account
    evaluationCredentials = assume_role('arn:aws:iam::'+account_id+':role/OrgConfigRuleEvalsRole2')
    # Create AWS SDK clients & initialize custom rule parameters
    config = boto3.client('config',
        aws_access_key_id=executionCredentials['AccessKeyId'],
        aws_secret_access_key=executionCredentials['SecretAccessKey'],
        aws_session_token=executionCredentials['SessionToken'],
    )
    response = config.put_evaluations(
       Evaluations=[
            {
                'ComplianceResourceType': invoking_event['configurationItem']['resourceType'],
                'ComplianceResourceId': resource_id,
                'ComplianceType': compliance_value,
                'OrderingTimestamp': invoking_event['notificationCreationTime']
            },
       ],
       ResultToken=event['resultToken'])
