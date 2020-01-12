# aws-vpc-flowlogs

**NOTE: aws-vpc-flowlogs are no longer deployed using these templages.**
**VPC Flow Log enablement is done in the base-vpc-from-parameter Stackset.**
**AWS Config rules to enforce enablement is done in the BaseConfigRules Stackset.**
**AWS Config is enabled in Enable-Config Stackset.**

## Overview
Cloudformation templates:
  * CentralLoggingSetup: Initial creation of Kinesis Stream, IAM policy, S3 bucket, KMS keys (currently not being used as QRadar was not able to decrypt the files), and Log Destionation PolicyName
StackSet Templates:
  * AccountLoggingSetup: Run against LoBs to setup a Logs Subscription Filter
  * VPCFlowLogChecker: Run against LoBs that setup the lambda_function, Config Rule and IAM Permissions
  * Config: Sets up AWS Config for accounts with a few basic rules.
Lambda:
  * cloudwatchParser: Unzips and decodes cloudwatch logs that come in.
  * lambda_function: Checks to see if VPC Flow logs are enabled, if not, creates them.
  * VPCFlowLog-Checker.zip: Zipped lambba_function that is stored in S3 and pulled down by LoBs

## How to use
#### If this is the first time any StackSets have been run, or the first time AWS Config has been used do the following:
 * Line of Business Acount: Run StackSetExecutionRole.yml in the region you will be working with (US-WEST-2)
 * StackSet Account: (pge-it-stackset) Add the new account number to it to the existing Config-Setup StackSet and run it. This will do the first time configuration of AWS Config and setup its S3 bucket. **WARNING: If you skip this step the vpc-flow-logs log group will not be created and the EnableLogSubscriptionFilters stackset will fail!
 * StackSet Account: Edit bucket policy for pge-central-lambda (under Permissions) and add:
 Example:

 ```
    {
        "Sid": "Allow Account: <name of account>",
        "Effect": "Allow",
        "Principal": {
            "AWS": "arn:aws:iam::############:role/AWSCloudFormationStackSetExecutionRole"
        },
        "Action": [
            "s3:Get*",
            "s3:List*"
        ],
        "Resource": [
            "arn:aws:s3:::pge-central-lambda",
            "arn:aws:s3:::pge-central-lambda/*"
        ]
    }
```
This allows the new LoB to pull down Lambda zip files to set up in their personal acocunt.

#### If those steps have been completed already, please continue below:
1. StackSet Account: Edit the CentralLoggingSetup.yaml file and update the following resource:    
 * VPCFlowLogsDestination:
    Type: 'AWS::Logs::Destination'

  The following will need to be added to the policy to allow Log Subscriptions:

  ```
  - '{"Effect" : "Allow", "Principal" : {"AWS" : "'
  - '############'
  - '" }, "Action" : "logs:PutSubscriptionFilter", "Resource" : "arn:aws:logs:'
  - !Ref AWS::Region
  - ':'
  - !Ref AWS::AccountId
  - ':destination:VPCFlowLogsDestination"},'  
  ```

The ######## is the account number for the new LoB.

2. StackSet Account: Run an update on CentralLoggingSetup.yaml (this is a normal CloudFormation template not a StackSet)

3. StackSet Account: Open the existing VPCFlowLogEnforcement
 * Open Manage  StackSets
 * Create StackSet
 * Add LoB Account Number and Region and go through the remainder of the prompts

 4. This will begin the enforcement of VPC Flows Logs in the new account. VPC Flow Logs groups are automatically generated, but can take 3-7 minutes. You can either wait or log in and check that vpc-flow-log log group has been created in CloudWatch.  Note, an EC2 instance that can generate traffic will help speed the creation of the vpc-flow-logs log group.  

 5. StackSet Account: Open the existing EnableLogSubscriptionFilters
  * Open Manage  StackSets
  * Create StackSet
  * Add LoB Account Number and Region and go through the remainder of the prompts
