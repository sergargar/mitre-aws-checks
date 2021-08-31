# Script for AWS Compliance Checks

Script for analyzing the compliance of your AWS account based on the adversary techniques on the [MITRE ATT&CK Iaas Matrix](https://attack.mitre.org/matrices/enterprise/cloud/iaas/).


## Description

An in-depth paragraph about your project and overview of use.

## Getting Started

### Dependencies

* It is necessary to have Python3 installed with the packages boto3 and termcolor
* The packages can be installed with the following command:
```
pip3 install boto3 termcolor
```

### User Creation

* The script needs the following permissions to run all the checks:
```
cloudtrail:describetrails
config:describeconfigurationrecorderstatus
guardduty:listdetectors
inspector:listassessmenttemplates
inspector:listassessmentruns
inspector:describeassessmentruns
ec2:describeflowlogs
ec2:describevolumes
ec2:describevpcs
ec2:describesecuritygroups
s3:getaccountpublicaccessblock
s3:ListAllMyBuckets
s3:GetBucketPublicAccessBlock
s3:GetEncryptionConfiguration
s3:GetBucketVersioning
iam:GetAccountSummary
iam:ListUsers
iam:ListAccessKeys
iam:ListMFADevices
iam:GetServiceLastAccessedDetails
iam:ListVirtualMFADevices
iam:GenerateServiceLastAccessedDetails
iam:GetAccountPasswordPolicy
```
* To facilitate the creation of these permissions, this repository has a [CloudFormation template](https://github.com/sergargar/mitre-aws-checks/blob/main/user-creation.yaml) to automatically deploy an user with the necessary permissions.
* Once the stack is created with the template, it gives you the access and secret keys of the new user in the Output Section.
* Finally, both the output credentials and the region to be analyzed must be configured locally through the following command:
```
aws configure
```

### Customize verification functions

* The following parameters can be customized in some functions:

| Function                 | Input Parameter                                                                                          | Description                                                                                                                                                                                           |
|-------------------------|----------------------------------------------------------------------------------------------------|-------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| inactive_users          | days_without_access                                                                                | Days without access of a user to be considered as inactive.                                                                                                                                   |
| access_keys_rotation    | keys_older_than_days                                                                               | Days old of the access keys so that they are rotated.                                                                                                                                         |
| s3_public_access        | account                                                                                            | AWS account where you want to verify the public access policies of S3.                                                                                                                           |
| strong_password_policy  | password_length, password_expiration_days, last_passwords_reuse                                                                                    | Minimum length and maximum expiration days of user passwords, and the number of last passwords that cannot be reused, required in the password policy of the AWS account.          |
| least_privilege_iam     | JobId                                                                                              | Job ID that the user has previously generated with the AWS call generate_service_last_accessed_details(Arn=<entityArn>,Granularity='ACTION_LEVEL'), choosing the entity to analyze. |
|  | days_without_being_used |  Days without using a service and / or actions by an entity for it to be considered as unused.                                                                                                                                                                                                     |
| inspector_enabled       | days_since_last_assessment                                                                         | Days since the last Inspector evaluation to be considered non-compliant.                                                                                                                  |                                                                                                       |

### Executing program

* Once the user is created and the credentials were configured, the script can be executed with:
```
python3 main.py
```



## MITRE ATT&CK Relationship

* The functions of the script can mitigate the following adversary techniques that are describe in the [IaaS Matrix](https://attack.mitre.org/matrices/enterprise/cloud/iaas/):

![Alt text](mitre-relationship.png?raw=true "MITRE ATT&CK Relationship")


## Version History

* 1.0
    * Initial Release
