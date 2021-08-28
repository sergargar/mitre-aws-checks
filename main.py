import json
import boto3
import os
import re
import datetime
import botocore.exceptions
from dateutil.tz import tzutc,tzlocal
from botocore.client import ClientError
from termcolor import colored

def main ():

	#mfa_is_enabled()

	days_without_access = 15
	#inactive_users(days_without_access)

	keys_older_than_days = 5
	#access_keys_rotation(keys_older_than_days)

	#ec2_public_ports()

	account = '198604771934'
	#s3_public_access(account)

	#s3_buckets_encrypted()

	#s3_buckets_versioned()

	#ebs_volumes_encrypted()

	#ebs_volumes_with_snapshot()

	password_length = 15
	password_expiration_days = 90
	last_passwords_reuse = 3
	#strong_password_policy(password_length,password_expiration_days,last_passwords_reuse)

	# Generate JobID with generate_service_last_accessed_details(Arn=<entityArn>,Granularity='ACTION_LEVEL')
	JobId='86bdc5fb-cad5-dff2-f957-1ab20213568b'
	days_without_being_used = 2
	#least_privilege_iam(JobId, days_without_being_used)

	#config_enabled()

	#guardduty_enabled()

	days_since_last_assessment = 4
	#inspector_enabled(days_since_last_assessment)

	#cloudtrail_multiregion_enabled()

	#vpc_flow_logs_enabled()
	
def mfa_is_enabled():
	print (colored("\n\n++++++++++++++ Check 1: MFAisEnabled ++++++++++++++",'yellow'))
	# Ensure hardware MFA is enabled for the root account
	client = boto3.client('iam')
	hardware_mfa_enabled = 1
	response = client.get_account_summary()['SummaryMap']
	if response['AccountMFAEnabled'] > 0:
		response1 = client.list_virtual_mfa_devices(AssignmentStatus='Assigned')
		for mfa in response1['VirtualMFADevices']:
			if "root" in mfa['SerialNumber']:
				hardware_mfa_enabled = 2
			else:
				hardware_mfa_enabled = 0
	if hardware_mfa_enabled == 1:
		print(colored("OK: Hardware MFA is enabled for root user.",'green'))
	elif hardware_mfa_enabled == 2:
		print(colored("FAIL: Virtual MFA (not hardware MFA) is enabled for root user.",'red'))
	else:
		print(colored("FAIL: No MFA was enabled for root user.",'red'))

	# Ensure virtual MFA is enabled for all users
	list_users_paginator = client.get_paginator('list_users')
	for page in list_users_paginator.paginate():
		for user in page['Users']:
			if len(client.list_mfa_devices(UserName=user['UserName'])['MFADevices']) < 1 :
				print(colored("FAIL: No MFA is enabled for user: "+user['UserName'],'red'))               
			else:
				print(colored("OK: MFA is enabled for user: "+user['UserName'],'green'))

def inactive_users(days):
	print(colored("\n\n++++++++++++++ Check 2: InactiveUsers ++++++++++++++",'yellow'))
	# Ensure there are no users without accessing during certain days
	client = boto3.client('iam')
	date = datetime.datetime.now().replace(tzinfo=tzutc())
	list_users_paginator = client.get_paginator('list_users')
	for page in list_users_paginator.paginate():
		for user in page['Users']:
			try:
				creation_date = user['CreateDate']+datetime.timedelta(hours=+2)
				last_logged = user['PasswordLastUsed']+datetime.timedelta(hours=+2)
				time_since_logged = date-last_logged
				days_since_logged = time_since_logged.days
			except KeyError: # No tracking period --> creation date
				time_since_creation = date-creation_date
				days_since_logged = time_since_creation.days
				pass
			if days_since_logged > days:
				print(colored("FAIL: User "+user['UserName']+" not logged for more than " +str(days)+ " days ("+str(days_since_logged)+" days).",'red'))
			else:
				print(colored("OK: User "+user['UserName']+" has been recently active " +str(days_since_logged)+ " days ago.",'green'))

def access_keys_rotation(days):
	print(colored("\n\n++++++++++++++ Check 3: RotateAccessKeys ++++++++++++++",'yellow'))	
	# Ensure there are no users with access keys older than x days
	client = boto3.client('iam')
	date = datetime.datetime.now().replace(tzinfo=tzutc())
	older_keys = 1
	list_users_paginator = client.get_paginator('list_users')
	for page in list_users_paginator.paginate():
		for user in page['Users']:
			user_keys = client.list_access_keys(UserName=user['UserName'])['AccessKeyMetadata']
			if len(user_keys) > 1 :
				for keys in user_keys:
					creation_keys = keys['CreateDate']+datetime.timedelta(hours=+2)
					keys_time = date-creation_keys
					if keys_time.days > days:
						older_keys = 0
			if older_keys == 0 :
				print(colored("FAIL: User "+user['UserName']+" has keys older than " +str(days)+ " days ("+str(keys_time.days)+" days).",'red'))
			else:
				print(colored("OK: User "+user['UserName']+" has NOT keys older than " +str(days)+ ".",'green'))

def ec2_public_ports():
	print (colored("\n\n++++++++++++++ Check 4: EC2PublicPorts ++++++++++++++",'yellow'))
	# Ensure there are no security groups with open ports
	client = boto3.client('ec2')
	describe_sg_paginator = client.get_paginator('describe_security_groups')
	for page in describe_sg_paginator.paginate():
		for sg in page['SecurityGroups']:
			port_open = 0
			ports = ""
			for rule in sg['IpPermissions']:
				for ip in rule['IpRanges']:
					if ip['CidrIp'] == "0.0.0.0/0":
						port_open = 1
						ports = ports + str(rule['FromPort']) + " "
			if port_open == 1 :
				print (colored("FAIL: Security group "+sg['GroupName']+" has open port(s) ( " + ports +").",'red'))
			else:
				print (colored("OK: Security group "+sg['GroupName']+" has NO open ports.",'green'))

def s3_public_access(account):
	print (colored("\n\n++++++++++++++ Check 5: EC2PublicPorts ++++++++++++++",'yellow'))	
	# Ensure there are no public S3 buckets
	s3 = boto3.resource('s3')
	s3_client = boto3.client('s3')
	s3_control = boto3.client('s3control')
	bucket_account_is_public = True
	public_buckets = ""
	bucket_list = [bucket.name for bucket in s3.buckets.all()]
	# 1. Check if public buckets are restricted at account level
	account_bucket_public_access = s3_control.get_public_access_block(AccountId = account)['PublicAccessBlockConfiguration']
	if account_bucket_public_access['IgnorePublicAcls'] and account_bucket_public_access['RestrictPublicBuckets']:
		bucket_account_is_public = False
	if bucket_account_is_public:
		# 2. If public access is not blocked at account level, check it at each bucket level
		for bucket in bucket_list:
			bucket_public_access = s3_client.get_public_access_block(Bucket = bucket)['PublicAccessBlockConfiguration']
			if not bucket_public_access['IgnorePublicAcls'] and not account_bucket_public_access['RestrictPublicBuckets']:
				public_buckets = public_buckets + bucket + " "
	if public_buckets == "" and not bucket_account_is_public:
		print (colored("OK: There are no public S3 buckets in the account.",'green'))
	elif public_buckets == "" and bucket_account_is_public:
		print (colored("FAIL: Block public access is disabled at account level.",'red'))
	else:
		print (colored("FAIL: The bucket(s) "+public_buckets+"are public.",'red'))

def s3_buckets_encrypted():
	print (colored("\n\n++++++++++++++ Check 6: S3BucketsEncrypted ++++++++++++++",'yellow'))	
	# Ensure there are no unencrypted S3 buckets
	s3 = boto3.resource('s3')
	s3_client = boto3.client('s3')
	unencrypted_buckets = ""
	bucket_list = [bucket.name for bucket in s3.buckets.all()]
	for bucket in bucket_list:
		try:
			bucket_encryption = s3_client.get_bucket_encryption(Bucket = bucket)
		except ClientError as e: # No encryption configuration
			unencrypted_buckets = unencrypted_buckets + bucket + " "
			pass
	if unencrypted_buckets == "" :
		print (colored("OK: There are no unencrypted buckets.",'green'))
	else:
		print (colored("FAIL: The bucket(s) "+unencrypted_buckets+"are unencrypted.",'red'))

def s3_buckets_versioned():
	print (colored("\n\n++++++++++++++ Check 7: S3BucketsVersioned ++++++++++++++",'yellow'))	
	# Ensure there are no S3 buckets without versioning
	s3 = boto3.resource('s3')
	s3_client = boto3.client('s3')
	unversioned_buckets = ""
	bucket_list = [bucket.name for bucket in s3.buckets.all()]
	for bucket in bucket_list:
		bucket_versioning = s3_client.get_bucket_versioning(Bucket = bucket)
		if 'Status' not in bucket_versioning or 'Enabled' not in bucket_versioning['Status']:
			unversioned_buckets = unversioned_buckets + bucket + " "
	if unversioned_buckets == "" :
		print (colored("OK: There are no buckets without versioning.",'green'))
	else:
		print (colored("FAIL: The bucket(s) "+unversioned_buckets+"are unversioned.",'red'))

def ebs_volumes_encrypted():
	print (colored("\n\n++++++++++++++ Check 8: EBSVolumesEncrypted ++++++++++++++",'yellow'))	
	# Ensure there are no unencrypted EBS volumes
	client = boto3.client('ec2')
	unencrypted_volumes = ""
	describe_volumes_paginator = client.get_paginator('describe_volumes')
	for page in describe_volumes_paginator.paginate():
		for volume in page['Volumes']:
			if not volume['Encrypted']:
				unencrypted_volumes = unencrypted_volumes + volume['VolumeId'] + " "
	if unencrypted_volumes == "" :
		print (colored("OK: There are no unencrypted EBS volumes.",'green'))
	else:
		print (colored("FAIL: The EBS volume(s) "+unencrypted_volumes+"are unencrypted.",'red'))

def ebs_volumes_with_snapshot():
	print (colored("\n\n++++++++++++++ Check 9: EBSVolumesWithSnapshot ++++++++++++++",'yellow'))	
	# Ensure there are no unencrypted EBS volumes
	client = boto3.client('ec2')
	volumes_without = ""
	describe_volumes_paginator = client.get_paginator('describe_volumes')
	for page in describe_volumes_paginator.paginate():
		for volume in page['Volumes']:
			if 'SnapshotId' not in volume:
				volumes_without = volumes_without + volume['VolumeId'] + " "
	if volumes_without == "" :
		print (colored("OK: There are no EBS volumes without snapshots.",'green'))
	else:
		print (colored("FAIL: The EBS volume(s) "+volumes_without+"are unencrypted.",'red'))

def strong_password_policy(length,expiration,reuse):
	print (colored("\n\n++++++++++++++ Check 10: StrongPasswordPolicy ++++++++++++++",'yellow'))	
	# Ensure there is a strong password policy
	client = boto3.client('iam')
	try:
		account_policy = client.get_account_password_policy()['PasswordPolicy']
		strong_password = True

		if account_policy ['MinimumPasswordLength'] < length:
			strong_password = False

		if not account_policy ['RequireUppercaseCharacters'] or not account_policy ['RequireLowercaseCharacters'] or not account_policy ['RequireNumbers'] or not account_policy ['RequireSymbols']:
			strong_password = False

		if account_policy ['ExpirePasswords']:
			if account_policy ['MaxPasswordAge'] < expiration:
				strong_password = False
		else:
			strong_password = False

		if 'PasswordReusePrevention' in account_policy:
			if account_policy ['PasswordReusePrevention'] < reuse:
				strong_password = False
		else:
			strong_password = False
		
		if not strong_password:
			print (colored("FAIL: Password policy is not strong.",'red'))
		else: 
			print(colored("OK: Password policy is strong.",'green'))

	except client.exceptions.NoSuchEntityException:
		print(colored("FAIL: Password policy does not exist.",'red'))
		pass

def least_privilege_iam(JobId,days):
	print (colored("\n\n++++++++++++++ Check 11: LeastPrivilegeIAM ++++++++++++++",'yellow'))	
	# Ensure there are no permissions without being used
	client = boto3.client('iam')
	date = datetime.datetime.now().replace(tzinfo=tzutc())
	not_acessed_services = ""
	not_used_actions = ""
	advisor = client.get_service_last_accessed_details(JobId=JobId)
	for service in advisor['ServicesLastAccessed']:
		if service['TotalAuthenticatedEntities'] < 1:
			not_acessed_services = not_acessed_services + '\n' + service['ServiceName']
		elif 'TrackedActionsLastAccessed' in service:
			not_used_actions = not_used_actions + '\n' + service['ServiceName'] +": "
			for action in service['TrackedActionsLastAccessed']:
				if 'LastAccessedTime' in action:
					access_time = action['LastAccessedTime']
					if date+datetime.timedelta(days=-days) > access_time:
						not_used_actions = not_used_actions + action['ActionName'] + " "
				else:
					not_used_actions = not_used_actions + action['ActionName'] + " "
		else:
			access_time = service['LastAuthenticated']
			if date+datetime.timedelta(days=-days) > access_time:
					not_acessed_services = not_acessed_services + '\n' + service['ServiceName']
	if not_acessed_services == "" and not_used_actions=="" :
		print (colored("OK: AWS IAM is compliant with least privilege principle.",'green'))
	else: 
		print(colored("FAIL: The following services and/or actions are not being used:\n"+not_acessed_services+not_used_actions,'red'))

def config_enabled():
	print (colored("\n\n++++++++++++++ Check 12: ConfigEnabled ++++++++++++++",'yellow'))	
	# Ensure Config service is active
	client = boto3.client('config')
	config_active = True
	response = client.describe_configuration_recorder_status()['ConfigurationRecordersStatus']
	if response == []:
		config_active = False
	else:
		for recorder in response:
			if not recorder['recording']:
				config_active = False
	if config_active:
		print (colored("OK: AWS Config is tracking configuration changes.",'green'))
	else: 
		print(colored("FAIL: AWS Config is not enabled",'red'))

def guardduty_enabled():
	print (colored("\n\n++++++++++++++ Check 13: GuardDutyEnabled ++++++++++++++",'yellow'))	
	# Ensure GuardDuty service is active
	client = boto3.client('guardduty')
	response = client.list_detectors()
	if response['DetectorIds'] == []:
		print(colored("FAIL: AWS GuardDuty is not enabled",'red'))
	else:
		print (colored("OK: AWS GuardDuty is monitoring for malicious behavior.",'green'))

def inspector_enabled(days):
	print (colored("\n\n++++++++++++++ Check 14: InspectorEnabled ++++++++++++++",'yellow'))	
	# Ensure Inspector service is active
	client = boto3.client('inspector')
	response = client.list_assessment_templates()
	inspector_active = True
	date = datetime.datetime.now().replace(tzinfo=tzlocal())
	if response['assessmentTemplateArns'] == []:
		inspector_active = False
	for template in response['assessmentTemplateArns']:
		runs = client.list_assessment_runs(assessmentTemplateArns=[template])
		for run in runs['assessmentRunArns']:
			response = client.describe_assessment_runs(assessmentRunArns=[run])
			if date+datetime.timedelta(days=-days) > response['assessmentRuns'][0]['completedAt']:
				inspector_active = False
	if not inspector_active:
		print(colored("FAIL: AWS Inspector is not enabled or assessment was not run within the last "+str(days)+" days.",'red'))
	else:
		print (colored("OK: AWS Inspector has run an assessment within the last "+str(days)+" days.",'green'))

def cloudtrail_multiregion_enabled():
	print (colored("\n\n++++++++++++++ Check 15: CloudTrailMultiRegionEnabled ++++++++++++++",'yellow'))	
	# Ensure CloudTrail service is active and all trails are multiregion
	client = boto3.client('cloudtrail', region_name='eu-west-1')
	response = client.describe_trails()
	trails_not_multiregion = ""
	for trail in response['trailList']:
		if not trail['IsMultiRegionTrail']:
			trails_not_multiregion = trails_not_multiregion + trail['Name'] + " "
	if response['trailList'] == []:
		print(colored("FAIL: Cloudtrail is not enabled.",'red'))
	if trails_not_multiregion == "" :
		print (colored("OK: All CloudTrail trail(s) are multiregion.",'green'))
	else:
		print(colored("FAIL: The CloudTrail trail(s) "+trails_not_multiregion+"are not multiregion.",'red'))

def vpc_flow_logs_enabled():
	print (colored("\n\n++++++++++++++ Check 16: VPCFlowLogsEnabled ++++++++++++++",'yellow'))	
	# Ensure VPC Flow logs are enabled for all VPCs
	client = boto3.client('ec2')
	response = client.describe_vpcs()
	vpc_without_logs = ""
	for vpc in response['Vpcs']:
		flow_logs = client.describe_flow_logs(Filters=[{'Name':'resource-id','Values':[vpc['VpcId']]}])
		if flow_logs['FlowLogs'] == []:
			vpc_without_logs = vpc_without_logs + vpc['VpcId']+ " "
	if vpc_without_logs == "" :
		print (colored("OK: All VPCs has Flow Logs activated.",'green'))
	else:
		print(colored("FAIL: The VPC(s) "+vpc_without_logs+"have no active Flow Logs.",'red'))

if __name__ == "__main__":
	main()