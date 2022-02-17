#!/usr/bin/python3

# Based on https://github.com/awslabs/aws-security-benchmark/blob/672cacf5e8244d7b090ed6de613e91139b585dbd/aws_cis_foundation_framework/aws-cis-foundation-benchmark-checklist.py
# AWS CIS Benchmark v1.3.0
import csv
import time
import sys
import re
import getopt
from datetime import datetime
import boto3  # python3 -m pip install boto3
from botocore.exceptions import ClientError
from botocore.config import Config
from colorama import Fore, Style
import json

IAM_CLIENT = boto3.client('iam', config=Config(
    connect_timeout=5, read_timeout=60, retries={'max_attempts': 20}))
S3_CLIENT = boto3.client('s3', config=Config(
    connect_timeout=5, read_timeout=60, retries={'max_attempts': 20}))
PROGRESS = -1
TOTAL_CHECKS = 59


def banner():
    print("""

                                                                                
                                        (@@@@@@@@@@@.                             _____  __      __  _________                      
                                    @@@/*************@@%                          /  _  \/  \    /  \/   _____/ ____   _____   ____  
                                 .@@@@@@@@@%%@#@@@@@@@@@@@#@#@@,                 /  /_\  \   \/\/   /\_____  \ /  _ \ /     \_/ __ \ 
                                #@(***@@@#@%%@@////@@@@@#@#@@                   /    |    \        / /        (  <_> )  Y Y  \  ___/ 
                               ,@%**********@@/////(@****%@*                    \____|__  /\__/\  / /_______  /\____/|__|_|  /\___  >
                               @@***********#@(////(@*****@@                            \/      \/          \/             \/     \/ 
                              @@*************@@////@@*****@@                    _________ .___  _________                            
                            *@@%**************&@&%@#******@@                    \_   ___ \|   |/   _____/                           
                           @@*@@****************@@*******@@                     /    \  \/|   |\_____  \  
                         @@****/@@**********************@@                      \     \___|   |/        \ 
                      ,@@*********@@@%*****************@@.                       \______  /___/_______  / 
                    @@@********************************@@                               \/            \/ 
                 .@@/**********************************%@,                      _________ .__    
                .@&*************************************@@                      \_   ___ \|  |__   ____   ____ |  | __ ___________   
               .@&***************************************@@                     /    \  \/|  |  \_/ __ \_/ ___\|  |/ // __ \_  __ \  
              .@&*****************************************@@                    \     \___|   Y  \  ___/\  \___|    <\  ___/|  | \/  
             .@&*******************************************@@                    \______  /___|  /\___  >\___  >__|_ \\___  >__|     
                                                                                        \/     \/     \/     \/     \/    \/         

                                                                                  v1.0
                                                                                  by Fiti@Secforce LTD



    """)
    return


def printProgressBar(iteration, total, prefix='Progress', suffix='Complete', decimals=1, length=50, fill='█', printEnd="\r"):
    """
    Call in a loop to create terminal progress bar
    @params:
        iteration   - Required  : current iteration (Int)
        total       - Required  : total iterations (Int)
        prefix      - Optional  : prefix string (Str)
        suffix      - Optional  : suffix string (Str)
        decimals    - Optional  : positive number of decimals in percent complete (Int)
        length      - Optional  : character length of bar (Int)
        fill        - Optional  : bar fill character (Str)
        printEnd    - Optional  : end character (e.g. "\r", "\r\n") (Str)
    """
    percent = ("{0:." + str(decimals) + "f}").format(100 *
                                                     (iteration / float(total)))
    filledLength = int(length * iteration // total)
    bar = fill * filledLength + '-' * (length - filledLength)
    print(f'\r{prefix} |{bar}| {percent}% {suffix}',
          end=printEnd, file=sys.stderr)
    # Print New Line on Complete
    if iteration == total:
        print()


def increment_progress():
    global PROGRESS
    global TOTAL_CHECKS
    PROGRESS += 1
    printProgressBar(PROGRESS, TOTAL_CHECKS)


def get_regions():
    try:
        client = boto3.client('ec2')
        regions = [region['RegionName']
                   for region in client.describe_regions()['Regions']]
        return regions
    except ClientError as e:
        print(Fore.RED + "EC2 Client error: " + str(e))
        print(Style.RESET_ALL)
        return False


def get_cred_report():
    x = 0
    status = ""
    try:
        while IAM_CLIENT.generate_credential_report()['State'] != "COMPLETE":
            time.sleep(2)
            x += 1
            if x > 10:
                status = "Fail: CredentialReport not available."
                break
        if "Fail" in status:
            print(Fore.RED + "ERROR: " + status)
            print(Style.RESET_ALL)
            return False

        response = IAM_CLIENT.get_credential_report()
        report = []
        reader = csv.DictReader(response['Content'].decode(
            "utf-8").splitlines(), delimiter=',')
        for row in reader:
            report.append(row)
        #print(json.dumps(report, indent=4, sort_keys=True))
        return report
    except ClientError as e:
        print(Fore.RED + "IAM Client ERROR: " + str(e))
        print(Style.RESET_ALL)
        return False


def get_account_password_policy():
    try:
        response = IAM_CLIENT.get_account_password_policy()
        return response['PasswordPolicy']
    except ClientError as e:
        if "cannot be found" in str(e):
            print(
                Fore.YELLOW + "[WARNING] IAM account password policy cannot be retrieved: " + str(e))
            print(Style.RESET_ALL)
            return False


def get_cloudtrails(regions):
    trails = dict()
    for n in regions:
        try:
            client = boto3.client('cloudtrail', region_name=n)
            response = client.describe_trails()
            temp = []
            for m in response['trailList']:
                if m['IsMultiRegionTrail'] is True:
                    if m['HomeRegion'] == n:
                        temp.append(m)
                else:
                    temp.append(m)
            if len(temp) > 0:
                trails[n] = temp
        except ClientError as e:
            # Non-existent region
            if "The security token included in the request is invalid" in str(e):
                pass
    return trails


def get_aws_info():
    region_list = get_regions()
    increment_progress()
    cred_report = get_cred_report()
    increment_progress()
    password_policy = get_account_password_policy()
    increment_progress()
    cloudtrails = get_cloudtrails(region_list)
    increment_progress()
    return region_list, cred_report, password_policy, cloudtrails

# --- 1 Identity and Access Management ---
# 1.1 Maintain current contact details (Manual)
def control_1_1():
    result = "Manual"
    failReason = []
    offenders = []
    control = "1.1"
    description = "Maintain current contact details."
    failReason.append("Please, check contact details manually.")
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 1.2 Ensure security contact information is registered (Manual)
def control_1_2():
    result = "Manual"
    failReason = []
    offenders = []
    control = "1.2"
    description = "Ensure security contact information is registered."
    failReason.append("Please, check security contact details manually.")
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 1.3 Ensure security questions are registered in the AWS account (Manual)
def control_1_3():
    result = "Manual"
    failReason = []
    offenders = []
    control = "1.3"
    description = "Ensure security questions are registered in the AWS account."
    failReason.append("Please, check security questions manually.")
    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 1.4 Ensure no root user account access key exists (Automated)
def control_1_4(credreport):
    result = True
    failReason = []
    offenders = []
    control = "1.4"
    description = "Ensure no root account access key exists."

    if "Fail" in credreport:  # Report failure in control
        result = "Manual"
        failReason.append(
            "Error retrieving credreport. Please check manually.")
    else:
        if (credreport[0]['access_key_1_active'] == "true") or (credreport[0]['access_key_2_active'] == "true"):
            result = False
            failReason.append("Root have active access keys")
            client = boto3.client("sts")
            offenders.append(
                "Account ID " + str(client.get_caller_identity()["Account"]))

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 1.5 Ensure MFA is enabled for the "root user" account (Automated)
def control_1_5():
    result = True
    failReason = []
    offenders = []
    control = "1.5"
    description = "Ensure MFA is enabled for the root account"

    response = IAM_CLIENT.get_account_summary()
    if response['SummaryMap']['AccountMFAEnabled'] != 1:
        result = False
        failReason.append("Root account not using MFA")
        client = boto3.client("sts")
        offenders.append(
            "Account ID " + str(client.get_caller_identity()["Account"]))

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 1.6 Ensure hardware MFA is enabled for the "root user" account (Automated)
def control_1_6():
    result = True
    failReason = []
    offenders = []
    control = "1.6"
    description = "Ensure hardware MFA is enabled for the \"root user\" account."

    response = IAM_CLIENT.get_account_summary()
    if response['SummaryMap']['AccountMFAEnabled'] == 1:
        paginator = IAM_CLIENT.get_paginator('list_virtual_mfa_devices')
        response_iterator = paginator.paginate(AssignmentStatus='Any',)
        pagedResult = []
        for page in response_iterator:
            for n in page['VirtualMFADevices']:
                pagedResult.append(n)
        if "mfa/root-account-mfa-device" in str(pagedResult):
            failReason.append("Root account not using hardware MFA")
            result = False
            client = boto3.client("sts")
            offenders.append(
                "Account ID " + str(client.get_caller_identity()["Account"]))
    else:
        result = False
        failReason.append("Root account not using MFA")
        client = boto3.client("sts")
        offenders.append(
            "Account ID " + str(client.get_caller_identity()["Account"]))

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 1.7 Eliminate use of the root user for administrative and daily tasks (Automated)
def control_1_7(credreport):
    result = True
    failReason = []
    offenders = []
    control = "1.7"
    description = "Eliminate use of the root user for administrative and daily tasks."

    if "Fail" in credreport:  # Report failure
        result = "Manual"
        failReason.append(
            "Error retrieving credreport. Please check manually.")
    else:
        # Check if root is used in the last 24h
        now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00',
                            time.gmtime(time.time()))
        frm = "%Y-%m-%dT%H:%M:%S+00:00"
        try:
            pwdDelta = (datetime.strptime(
                now, frm) - datetime.strptime(credreport[0]['password_last_used'], frm))
            if (pwdDelta.days == 0) & (pwdDelta.seconds > 0):  # Used within last 24h
                result = False
                failReason.append("Root password used within 24h.")
        except:
            if credreport[0]['password_last_used'] == "N/A" or "no_information":
                pass
            else:
                result = "Manual"
                failReason.append("Something went wrong")
        try:
            key1Delta = (datetime.strptime(
                now, frm) - datetime.strptime(credreport[0]['access_key_1_last_used_date'], frm))
            if (key1Delta.days == 0) & (key1Delta.seconds > 0):  # Used within last 24h
                result = False
                failReason.append("Root Key1 used within 24h.")
        except:
            if credreport[0]['access_key_1_last_used_date'] == "N/A" or "no_information":
                pass
            else:
                result = "Manual"
                failReason.append("Something went wrong")
        try:
            key2Delta = datetime.strptime(
                now, frm) - datetime.strptime(credreport[0]['access_key_2_last_used_date'], frm)
            if (key2Delta.days == 0) & (key2Delta.seconds > 0):  # Used within last 24h
                failReason.append("Root key2 used within 24h.")
                result = False
        except:
            if credreport[0]['access_key_2_last_used_date'] == "N/A" or "no_information":
                pass
            else:
                result = "Manual"
                failReason.append("Something went wrong")
        if result == False:
            client = boto3.client("sts")
            offenders.append(
                "Account ID " + str(client.get_caller_identity()["Account"]))

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 1.8 Ensure IAM password policy requires minimum length of 14 or greater (Automated)
def control_1_8(password_policy):
    result = True
    failReason = []
    offenders = []
    control = "1.8"
    description = "Ensure IAM password policy requires minimum length of 14 or greater."

    if password_policy is False:
        result = False
        failReason.append(
            "Account is using default IAM password policy (weak).")
    else:
        if password_policy['MinimumPasswordLength'] < 14:
            result = False
            failReason.append(
                "Password policy does not require at least 14 characters")
    if result == False:
        client = boto3.client("sts")
        offenders.append(
            "Account ID " + str(client.get_caller_identity()["Account"]))

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 1.9 Ensure IAM password policy prevents password reuse (Automated)
def control_1_9(password_policy):
    result = True
    failReason = []
    offenders = []
    control = "1.9"
    description = "Ensure IAM password policy prevents password reuse."

    if password_policy is False:
        result = False
        failReason.append(
            "Account is using default IAM password policy (weak).")
    else:
        try:
            if password_policy['PasswordReusePrevention'] >= 24:
                pass
            else:
                result = False
                failReason.append(
                    "Password policy does not prevent reusing last 24 passwords")
        except:
            result = False
            failReason.append(
                "Password policy does not prevent reusing last 24 passwords")
    if result == False:
        client = boto3.client("sts")
        offenders.append(
            "Account ID " + str(client.get_caller_identity()["Account"]))

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 1.10 Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password (Automated)
def control_1_10(credreport):
    result = True
    failReason = []
    offenders = []
    control = "1.10"
    description = "Ensure multi-factor authentication (MFA) is enabled for all IAM users that have a console password"

    if "Fail" in credreport:  # Report failure in control
        result = "Manual"
        failReason.append(
            "Error retrieving credreport. Please check manually.")
    else:
        for user in credreport:
            if user['password_enabled'] == "true":
                if user['mfa_active'] == "false":
                    result = False
                    failReason.append("No MFA on user " + user['user'] + ".")
                    offenders.append(user['arn'])

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 1.11 Do not setup access keys during initial user setup for all IAM users that have a console password (Manual)
def control_1_11():  # Work in progress
    result = True
    failReason = []
    offenders = []
    control = "1.11"
    description = "Do not setup access keys during initial user setup for all IAM users that have a console password."

    result = "Manual"
    failReason.append("Please, check this control manually.")

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 1.12 Ensure credentials unused for 90 days or greater are disabled (Automated)
def control_1_12(credreport):
    result = True
    failReason = []
    offenders = []
    control = "1.12"
    description = "Ensure credentials unused for 90 days or greater are disabled"

    if "Fail" in credreport:  # Report failure
        result = "Manual"
        failReason.append(
            "Error retrieving credreport. Please check manually.")
    else:
        now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00',
                            time.gmtime(time.time()))
        frm = "%Y-%m-%dT%H:%M:%S+00:00"
        # Look for unused credentails
        for user in credreport:
            if user['password_enabled'] == "true":
                try:
                    delta = datetime.strptime(
                        now, frm) - datetime.strptime(user['password_last_used'], frm)
                    # Verify password have been used in the last 90 days
                    if delta.days > 90:
                        result = False
                        failReason.append(
                            "Credentials unused > 90 days detected for user " + user['user'] + " (password).")
                        offenders.append(user['arn'] + ":password")
                except:
                    pass  # Never used
            if user['access_key_1_active'] == "true":
                try:
                    delta = datetime.strptime(
                        now, frm) - datetime.strptime(user['access_key_1_last_used_date'], frm)
                    # Verify password have been used in the last 90 days
                    if delta.days > 90:
                        result = False
                        failReason.append(
                            "Credentials unused > 90 days detected for user " + user['user'] + " (key1).")
                        offenders.append(user['arn'] + ":key1")
                except:
                    pass
            if user['access_key_2_active'] == "true":
                try:
                    delta = datetime.strptime(
                        now, frm) - datetime.strptime(user['access_key_2_last_used_date'], frm)
                    # Verify password have been used in the last 90 days
                    if delta.days > 90:
                        result = False
                        failReason.append(
                            "Credentials unused > 90 days detected for user " + user['user'] + " (key2).")
                        offenders.append(user['arn'] + ":key2")
                except:
                    # Never used
                    pass

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 1.13 Ensure there is only one active access key available for any single IAM user (Automated)
def control_1_13():
    result = True
    failReason = []
    offenders = []
    control = "1.13"
    description = "Ensure there is only one active access key available for any single IAM user."

    user_paginator = IAM_CLIENT.get_paginator('list_users')
    for response in user_paginator.paginate():
        for user in response['Users']:
            key_paginator = IAM_CLIENT.get_paginator('list_access_keys')
            for userkeys in key_paginator.paginate(UserName=user['UserName']):
                if len(userkeys['AccessKeyMetadata']) > 1:
                    count = 0
                    for key in userkeys['AccessKeyMetadata']:
                        #print(key['UserName'] + ":" + key['AccessKeyId'] + ":" + key['Status'])
                        if key['Status'] == "Active":
                            count += 1
                    if count > 1:
                        result = False
                        failReason.append(
                            "User " + user['UserName'] + " has " + str(count) + " active keys.")
                        offenders.append(user['Arn'])

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 1.14 Ensure access keys are rotated every 90 days or less (Automated)
def control_1_14(credreport):
    result = True
    failReason = []
    offenders = []
    control = "1.14"
    description = "Ensure access keys are rotated every 90 days or less."

    if "Fail" in credreport:  # Report failure in control
        result = "Manual"
        failReason.append(
            "Error retrieving credreport. Please check manually.")
    else:
        now = time.strftime('%Y-%m-%dT%H:%M:%S+00:00',
                            time.gmtime(time.time()))
        frm = "%Y-%m-%dT%H:%M:%S+00:00"
        # Look for unused credentails
        for user in credreport:
            if user['access_key_1_active'] == "true":
                try:
                    delta = datetime.strptime(
                        now, frm) - datetime.strptime(user['access_key_1_last_rotated'], frm)
                    # Verify keys have rotated in the last 90 days
                    if delta.days > 90:
                        result = False
                        failReason.append(
                            "Key1 rotation > 90 days for user " + user['user'])
                        offenders.append(user['arn'] + ":unrotated key1")
                except:
                    pass
                try:
                    last_used_datetime = datetime.strptime(
                        user['access_key_1_last_used_date'], frm)
                    last_rotated_datetime = datetime.strptime(
                        user['access_key_1_last_rotated'], frm)
                    # Verify keys have been used since rotation.
                    if last_used_datetime < last_rotated_datetime:
                        result = False
                        failReason.append(
                            "Key1 rotation not used since rotation for user" + user['user'])
                        offenders.append(user['arn'] + ":unused key1")
                except:
                    pass
            if user['access_key_2_active'] == "true":
                try:
                    delta = datetime.strptime(
                        now, frm) - datetime.strptime(user['access_key_2_last_rotated'], frm)
                    # Verify keys have rotated in the last 90 days
                    if delta.days > 90:
                        result = False
                        failReason.append(
                            "Key2 rotation > 90 days for user" + user['user'])
                        offenders.append(user['arn'] + ":unrotated key2")
                except:
                    pass
                try:
                    last_used_datetime = datetime.strptime(
                        user['access_key_2_last_used_date'], frm)
                    last_rotated_datetime = datetime.strptime(
                        user['access_key_2_last_rotated'], frm)
                    # Verify keys have been used since rotation.
                    if last_used_datetime < last_rotated_datetime:
                        result = False
                        failReason.append(
                            "Key2 rotation not used since rotation for user" + user['user'])
                        offenders.append(user['arn'] + ":unused key2")
                except:
                    pass

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 1.15 Ensure IAM Users Receive Permissions Only Through Groups (Automated)
def control_1_15():
    result = True
    failReason = []
    offenders = []
    control = "1.15"
    description = "Ensure IAM Users Receive Permissions Only Through Groups"

    paginator = IAM_CLIENT.get_paginator('list_users')
    for response in paginator.paginate():
        for user in response['Users']:
            policies = IAM_CLIENT.list_attached_user_policies(
                UserName=user['UserName'])
            for policy in policies['AttachedPolicies']:
                if policy['PolicyName'] != []:
                    result = False
                    failReason.append(
                        user['UserName'] + " IAM user have inline policies attached: " + str(policy['PolicyName']))
                    offenders.append(user['Arn'])

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 1.16 Ensure IAM policies that allow full "*:*" administrative privileges are not attached (Automated)
def control_1_16():
    result = True
    failReason = []
    offenders = []
    control = "1.16"
    description = "Ensure IAM policies that allow full \"*:*\" administrative privileges are not created"

    paginator = IAM_CLIENT.get_paginator('list_policies')
    for response in paginator.paginate():
        for policy in response['Policies']:
            pol = IAM_CLIENT.get_policy_version(
                PolicyArn=policy['Arn'], VersionId=policy['DefaultVersionId'])
            # a policy may contain a single statement, a single statement in an array, or multiple statements in an array
            if isinstance(pol['PolicyVersion']['Document']['Statement'], list):
                for statement in pol['PolicyVersion']['Document']['Statement']:
                    try:
                        if statement['Effect'] == "Allow" and statement['Action'] == "*" and statement['Resource'] == "*":
                            result = False
                            failReason.append(
                                policy['Arn'] + " with full admin privileges")
                            offenders.append(policy['Arn'])
                    except Exception as e:  # NotAction instead of Action, we don't care about these ones
                        pass
            else:
                statement = pol['PolicyVersion']['Document']['Statement']
                try:
                    if statement['Effect'] == "Allow" and statement['Action'] == "*" and statement['Resource'] == "*":
                        result = False
                        failReason.append(
                            policy['Arn'] + " with full admin privileges")
                        offenders.append(policy['Arn'])
                except Exception as e:  # NotAction instead of Action, we don't care about these ones
                    pass
    if len(offenders) == 1 and offenders[0] == "arn:aws:iam::aws:policy/AdministratorAccess":
        result = "Manual"
        failReason.append(
            "AdministratorAccess is a default policy and not an issue by itself. Please verify which users have access to this policy to verify Risk.")

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 1.17 Ensure a support role has been created to manage incidents with AWS Support (Automated)
def control_1_17():
    result = True
    failReason = []
    offenders = []
    control = "1.17"
    description = "Ensure a support role has been created to manage incidents with AWS Support"

    try:
        response = IAM_CLIENT.list_entities_for_policy(
            PolicyArn='arn:aws:iam::aws:policy/AWSSupportAccess')
        if response['PolicyGroups'] == [] and response['PolicyUsers'] == [] and response['PolicyRoles'] == []:
            result = False
            failReason.append(
                "AWSSupportAccess attached to no user, group or role.")
    except:
        result = False
        failReason.append("AWSSupportAccess policy not created")
    if result == False:
        client = boto3.client("sts")
        offenders.append(
            "Account ID " + str(client.get_caller_identity()["Account"]))

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 1.18 Ensure IAM instance roles are used for AWS resource access from instances (Manual)
def control_1_18(region_list):
    result = True
    failReason = []
    offenders = []
    control = "1.18"
    description = "Ensure IAM instance roles are used for AWS resource access from instances."

    for region in region_list:
        try:
            client = boto3.client('ec2', region_name=region, config=Config(
                connect_timeout=5, read_timeout=60, retries={'max_attempts': 20}))
            response = client.describe_instances()
            if bool(response['Reservations']):
                for reservation in response['Reservations']:
                    for instance in reservation['Instances']:
                        try:
                            if instance['IamInstanceProfile']:
                                pass
                        except:
                            result = False
                            failReason.append(
                                "Region " + region + ", " + instance['InstanceId'] + " instance with no IAM role assigned for EC2")
                            offenders.append(
                                "Region " + region + ":Instance " + instance['InstanceId'])
        except ClientError as e:
            if e.response['Error']['Code'] == 'AuthFailure':  # Non existing regions
                pass

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 1.19 Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed (Automated)
def control_1_19():
    result = True
    failReason = []
    offenders = []
    control = "1.19"
    description = "Ensure that all the expired SSL/TLS certificates stored in AWS IAM are removed."

    now = time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime(time.time()))
    frm = "%Y-%m-%dT%H:%M:%SZ"
    paginator = IAM_CLIENT.get_paginator('list_server_certificates')
    for response in paginator.paginate():
        if response['ServerCertificateMetadataList'] == []:
            pass  # No certificates
        else:
            for certificate in response['ServerCertificateMetadataList']:
                delta = datetime.strptime(
                    now, frm) - datetime.strptime(certificate['Expiration'], frm)
                if delta.days > 0:  # Expired certificate
                    result = False
                    failReason.append(
                        "Certificate " + certificate['ServerCertificateName'] + "expired.")
                    offenders.append(certificate['Arn'])

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 1.20 Ensure that S3 Buckets are configured with 'Block public access (bucket settings)' (Automated)
def control_1_20():
    result = True
    failReason = []
    offenders = []
    control = "1.20"
    description = "Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'"

    try:
        response = S3_CLIENT.list_buckets()
        for bucket in response['Buckets']:
            try:
                accessblock = S3_CLIENT.get_public_access_block(
                    Bucket=bucket['Name'])
                if "false" in str(accessblock):
                    result = False
                    failReason.append(
                        bucket['Name'] + " bucket 'Block public access' misconfiguration.")
                    offenders.append("S3 Bucket:" + bucket['Name'])
            except ClientError as e:
                if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                    result = False
                    failReason.append(
                        bucket['Name'] + " bucket 'Block public access' disabled.")
                    offenders.append("S3 Bucket:" + bucket['Name'])
    except ClientError as e:
        result = "Manual"
        failReason.append("ERROR: " + str(e))

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 1.21 Ensure that IAM Access analyzer is enabled (Automated)
def control_1_21(regions):
    result = True
    failReason = []
    offenders = []
    control = "1.21"
    description = "Ensure that S3 Buckets are configured with 'Block public access (bucket settings)'Ensure that IAM Access analyzer is enabled."

    for region in regions:
        try:
            client = boto3.client('accessanalyzer', region_name=region)
            response = client.list_analyzers()
            if response['analyzers'] == []:
                result = False
                failReason.append(
                    "No Access Analyzers for " + region + " region.")
            else:
                for analyzer in response['analyzers']:
                    if analyzer['status'] != "ACTIVE":
                        result = False
                        failReason.append(
                            analyzer['name'] + " status not 'ACTIVE'.")
        except ClientError as e:
            # Non-existent region
            if "The security token included in the request is invalid" in str(e):
                pass
            else:
                result = "Manual"
                failReason.append("ERROR: " + str(e))

        if result == False:
            client = boto3.client("sts")
            offenders.append(
                "Account ID " + str(client.get_caller_identity()["Account"]))

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 1.22 Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments (Manual)
def control_1_22():
    result = True
    failReason = []
    offenders = []
    control = "1.22"
    description = "Ensure IAM users are managed centrally via identity federation or AWS Organizations for multi-account environments."

    result = "Manual"
    failReason.append("Please, check security questions manually.")

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# --- 2. Storage ---
# 2.1 Simple Storage Service (S3)
# 2.1.1 Ensure all S3 buckets employ encryption-at-rest (Manual)
def control_2_1_1():
    result = True
    failReason = []
    offenders = []
    control = "2.1.1"
    description = "Ensure all S3 buckets employ encryption-at-rest"

    response = S3_CLIENT.list_buckets()
    for bucket in response['Buckets']:
        try:
            enc = S3_CLIENT.get_bucket_encryption(Bucket=bucket['Name'])
            rules = enc['ServerSideEncryptionConfiguration']['Rules']
            for rule in rules:
                if rule['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] != 'AES256' and rule['ApplyServerSideEncryptionByDefault']['SSEAlgorithm'] != 'aws:kms':
                    result = False
                    failReason.append(
                        "Wrong at-rest-encryption in " + bucket['Name'] + " bucket.")
                    offenders.append("S3 Bucket:" + bucket['Name'])
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                result = False
                failReason.append("No at-rest-encryption in " +
                                  bucket['Name'] + " bucket.")
                offenders.append("S3 Bucket:" + bucket['Name'])
            else:
                print("Bucket: %s, unexpected error: %s" % (bucket['Name'], e))

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 2.1.2 Ensure S3 Bucket Policy allows HTTPS requests (Manual)
def control_2_1_2():
    result = True
    failReason = []
    offenders = []
    control = "2.1.2"
    description = "Ensure S3 Bucket Policy allows HTTPS requests"

    response = S3_CLIENT.list_buckets()
    for bucket in response['Buckets']:
        try:
            policy = S3_CLIENT.get_bucket_policy(Bucket=bucket['Name'])
            safe_bucket = False
            policy_json = json.loads(policy['Policy'])  # Parsing policies
            for statement in policy_json['Statement']:
                if statement['Effect'] == "Deny" and statement['aws:SecureTransport'] == "false":
                    safe_bucket = True
            if not safe_bucket:
                result = False
                failReason.append(
                    "Bucket " + bucket['Name'] + " allowing HTTP traffic.")
                offenders.append("S3 Bucket:" + bucket['Name'])
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                result = False
                failReason.append(
                    "Bucket " + bucket['Name'] + " has no policy attached.")
                offenders.append("S3 Bucket:" + bucket['Name'])
            else:
                print("Bucket: %s, unexpected error: %s" % (bucket['Name'], e))
        except json.decoder.JSONDecodeError as e:
            print("Unexpected JSON error: " + str(e))

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 2.2 Elastic Compute Cloud (EC2)
# 2.2.1 Ensure EBS volume encryption is enabled (Manual)
def control_2_2_1(region_list):
    result = True
    failReason = []
    offenders = []
    control = "2.2.1"
    description = "Ensure EBS volume encryption is enabled"

    for region in region_list:  # I think S3 buckets are not attached to a specific region. if so, add this loop
        try:
            ec2_client = boto3.client('ec2', region_name=region)
            response = ec2_client.get_ebs_encryption_by_default()
            if response['EbsEncryptionByDefault'] != "True":
                result = False
                failReason.append(
                    region + "EC2 region with EBS volume encryption disabled by default.")
                offenders.append(region)
        except ClientError as e:
            if e.response['Error']['Code'] == 'AuthFailure':  # Non existing regions
                pass

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# --- 3. Logging ---
# 3.1 Ensure CloudTrail is enabled in all regions (Automated)
def control_3_1(cloudtrails):
    result = False
    failReason = []
    offenders = []
    control = "3.1"
    description = "Ensure CloudTrail is enabled in all regions"

    if bool(cloudtrails):
        for cloudtrail in cloudtrails:
            for trail in cloudtrails[cloudtrail]:
                if trail['IsMultiRegionTrail']:
                    client = boto3.client('cloudtrail', region_name=cloudtrail)
                    response = client.get_trail_status(Name=trail['TrailARN'])
                    if response['IsLogging'] is True:
                        result = True
                        break
                else:
                    failReason.append("No enabled multi region trails found")
                    offenders.append("Cloudtrails:NoMultiRegion")
    else:
        failReason.append("CloudTrails disabled in all regions")
        offenders.append("Cloudtrails:AllRegions")

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 3.2 Ensure CloudTrail log file validation is enabled (Automated)
def control_3_2(cloudtrails):
    result = True
    failReason = []
    offenders = []
    control = "3.2"
    description = "Ensure CloudTrail log file validation is enabled"

    if bool(cloudtrails):
        for cloudtrail in cloudtrails:
            for trail in cloudtrails[cloudtrail]:
                if trail['LogFileValidationEnabled'] == False:
                    result = False
                    failReason.append(
                        trail['TrailARN'] + " cloudtrail without log file validation enabled")
                    offenders.append(trail['TrailARN'])
    else:
        result = False
        failReason.append("CloudTrails disabled in all regions")
        offenders.append("Cloudtrails:AllRegions")

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 3.3 Ensure the S3 bucket used to store CloudTrail logs is not publicly accessible (Automated)
def control_3_3(cloudtrails):
    result = True
    failReason = []
    offenders = []
    control = "3.3"
    description = "Ensure the S3 bucket CloudTrail logs to is not publicly accessible."

    if bool(cloudtrails):
        for cloudtrail in cloudtrails:
            for trail in cloudtrails[cloudtrail]:
                if "S3BucketName" in str(trail):
                    try:
                        response = S3_CLIENT.get_bucket_acl(
                            Bucket=trail['S3BucketName'])
                        for p in response['Grants']:
                            if re.search(r'(global/AllUsers|global/AuthenticatedUsers)', str(p['Grantee'])):
                                result = False
                                failReason.append(
                                    trail['TrailARN'] + " publically accessible.")
                                offenders.append(
                                    trail['TrailARN'] + ":PublicBucket")
                    except Exception as e:
                        result = "Manual"
                        if "AccessDenied" in str(e):
                            offenders.append(
                                trail['TrailARN'] + ":AccessDenied")
                            failReason.append(
                                "Missing permissions to verify bucket ACL in " + trail['TrailARN'])
                        elif "NoSuchBucket" in str(e):
                            offenders.append(trail['TrailARN'] + ":NoBucket")
                            failReason.append(
                                trail['TrailARN'] + " Trailbucket doesn't exist.")
                        else:
                            offenders.append(
                                trail['TrailARN'] + ":CannotVerify")
                            failReason.append(
                                "Cannot verify bucket ACL in " + trail['TrailARN'])
                else:
                    result = False
                    offenders.append(trail['TrailARN'] + ":NoS3Logging")
                    failReason.append(
                        trail['TrailARN'] + " trail not configured to log to S3")
    else:
        result = False
        failReason.append("CloudTrails disabled in all regions")
        offenders.append("Cloudtrails:AllRegions")

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 3.4 Ensure CloudTrail trails are integrated with CloudWatch Logs (Automated)
def control_3_4(cloudtrails):
    result = True
    failReason = []
    offenders = []
    control = "3.4"
    description = "Ensure CloudTrail trails are integrated with CloudWatch Logs."

    if bool(cloudtrails):
        for cloudtrail in cloudtrails:
            for trail in cloudtrails[cloudtrail]:
                try:
                    if not "arn:aws:logs" in trail['CloudWatchLogsLogGroupArn']:
                        result = False
                        failReason.append(
                            trail['TrailARN'] + " trail without CloudWatch Logs.")
                        offenders.append(trail['TrailARN'])
                except:
                    result = False
                    failReason.append(
                        "CloudTrails without CloudWatch Logs discovered")
                    offenders.append(trail['TrailARN'])
    else:
        result = False
        failReason.append("CloudTrails disabled in all regions")
        offenders.append("Cloudtrails:AllRegions")

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 3.5 Ensure AWS Config is enabled in all regions (Automated)
def control_3_5(regions):
    result = True
    failReason = []
    offenders = []
    control = "3.5"
    description = "Ensure AWS Config is enabled in all regions"

    globalConfigCapture = False  # Only one region needs to capture global events
    for region in regions:
        try:
            configClient = boto3.client('config', region_name=region)
            response = configClient.describe_configuration_recorder_status()
            if response['ConfigurationRecordersStatus'] != []:
                try:
                    if response['ConfigurationRecordersStatus'][0]['recording'] != True:
                        result = False
                        failReason.append(
                            "Region " + region + ", not recording.")
                        offenders.append(region + ":NotRecording")
                except Exception as e:
                    result = "Manual"
                    failReason.append(
                        "Unexpected error in region " + region + ": " + str(e))
                # Verify that each region is capturing all events
                response = configClient.describe_configuration_recorders()
                try:
                    if response['ConfigurationRecorders'][0]['recordingGroup']['allSupported'] != True:
                        result = False
                        failReason.append(
                            "Region " + region + ", not capturing all/global events.")
                        offenders.append(region + ":NotAllEvents")
                except:
                    # This indicates that Config is disabled in the region and will be captured above.
                    pass
                # Check if region is capturing global events. Fail is verified later since only one region needs to capture them.
                try:
                    if response['ConfigurationRecorders'][0]['recordingGroup']['includeGlobalResourceTypes'] == True:
                        globalConfigCapture = True
                except:
                    pass
                # Verify the delivery channels
                response = configClient.describe_delivery_channel_status()
                try:
                    if response['DeliveryChannelsStatus'][0]['configHistoryDeliveryInfo']['lastStatus'] != "SUCCESS":
                        result = False
                        failReason.append(
                            "Region " + region + ", S3 or SNSDelivery error")
                        offenders.append(region + ":S3orSNSDelivery")
                except:
                    pass  # Will be captured by earlier rule
                try:
                    if response['DeliveryChannelsStatus'][0]['configStreamDeliveryInfo']['lastStatus'] != "SUCCESS":
                        result = False
                        failReason.append(
                            "Region " + region + ", S3 or SNSDelivery error")
                        offenders.append(region + ":SNSDelivery")
                except:
                    pass  # Will be captured by earlier rule

                # Verify that global events is captured by any region
                if globalConfigCapture is False:
                    result = False
                    failReason.append(
                        "Region " + region + ", Config not enabled to capture global events")
                    offenders.append("Global:NotRecording")
            else:
                result = False
                failReason.append(region + " Config not enabled")
                offenders.append(region + ":Disabled")
        except Exception as e:
            # Non-existent region
            if "The security token included in the request is invalid" in str(e):
                pass

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}
# 3.6 Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket (Automated)
def control_3_6(cloudtrails):
    result = True
    failReason = []
    offenders = []
    control = "3.6"
    description = "Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket"

    if bool(cloudtrails):
        for cloudtrail in cloudtrails:
            for trail in cloudtrails[cloudtrail]:
                try:
                    response = S3_CLIENT.get_bucket_logging(
                        Bucket=trail['S3BucketName'])
                except:
                    result = False
                    failReason.append(
                        trail['TrailARN'] + " trail not configured to log to S3.")
                    offenders.append(trail['TrailARN'])
                try:
                    if response['LoggingEnabled']:
                        pass
                except:
                    result = False
                    failReason.append(
                        trail['TrailARN'] + " trail S3 bucket with logging disabled")
                    offenders.append(
                        "Trail:" + trail['TrailARN'] + " - S3Bucket:" + trail['S3BucketName'])
    else:
        result = False
        failReason.append("CloudTrails disabled in all regions")

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 3.7 Ensure CloudTrail logs are encrypted at rest using KMS CMKs (Automated)
def control_3_7(cloudtrails):
    result = True
    failReason = []
    offenders = []
    control = "3.7"
    description = "Ensure CloudTrail logs are encrypted at rest using KMS CMKs"

    if bool(cloudtrails):
        for cloudtrail in cloudtrails:
            for trail in cloudtrails[cloudtrail]:
                try:
                    if trail['KmsKeyId']:
                        pass
                except:
                    result = False
                    failReason.append(
                        trail['TrailARN'] + " trail not using KMS CMK for encryption discovered")
                    offenders.append(trail['TrailARN'])
    else:
        result = False
        failReason.append("CloudTrails disabled in all regions")
        offenders.append("Cloudtrails:AllRegions")

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 3.8 Ensure rotation for customer created CMKs is enabled (Automated)
def control_3_8(regions):
    result = True
    failReason = []
    offenders = []
    control = "3.8"
    description = "Ensure rotation for customer created CMKs is enabled"

    for region in regions:
        try:
            kms_client = boto3.client('kms', region_name=region)
            paginator = kms_client.get_paginator('list_keys')
            response_iterator = paginator.paginate()
            for page in response_iterator:
                for key in page['Keys']:
                    try:
                        rotation = kms_client.get_key_rotation_status(
                            KeyId=key['KeyId'])
                        if rotation['KeyRotationEnabled'] == False:
                            key_description = kms_client.describe_key(
                                KeyId=key['KeyId'])
                            # Ignore service keys
                            if "Default master key that protects my" not in str(key_description['KeyMetadata']['Description']):
                                result = False
                                failReason.append(
                                    key_description['KeyMetadata']['Arn'] + ": KMS CMK rotation not enabled")
                                offenders.append(
                                    key_description['KeyMetadata']['Arn'])
                    except:
                        pass  # Ignore keys without permission, for example ACM key
        except Exception as e:
            # Non-existent region
            if "The security token included in the request is invalid" in str(e):
                pass

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 3.9 Ensure VPC flow logging is enabled in all VPCs (Automated)
def control_3_9(regions):
    result = True
    failReason = []
    offenders = []
    control = "3.9"
    description = "Ensure VPC flow logging is enabled in all VPCs."

    for region in regions:
        try:
            client = boto3.client('ec2', region_name=region, config=Config(
                connect_timeout=5, read_timeout=60, retries={'max_attempts': 20}))
            flow_logs = client.describe_flow_logs()
            if flow_logs['FlowLogs'] == []:
                result = False
                failReason.append(
                    "Flow logs disabled on VPCs in region " + region)
                offenders.append(region)
        except ClientError as e:
            if e.response['Error']['Code'] == 'AuthFailure':  # Non existing regions
                pass

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 3.10 Ensure that Object-level logging for write events is enabled for S3 bucket (Automated)
def control_3_10(cloudtrails):
    result = True
    failReason = []
    offenders = []
    control = "3.10"
    description = "Ensure that Object-level logging for write events is enabled for S3 bucket."

    if bool(cloudtrails):
        for cloudtrail in cloudtrails:
            client = boto3.client('cloudtrail', region_name=cloudtrail, config=Config(
                connect_timeout=5, read_timeout=60, retries={'max_attempts': 20}))
            for trail in cloudtrails[cloudtrail]:
                try:
                    response = client.get_event_selectors(
                        TrailName=trail['Name'])
                    for eventselector in response['EventSelectors']:
                        if eventselector['DataResources'] == []:
                            result = False
                            failReason.append(
                                trail['TrailARN'] + " trail with Object-level logging disabled.")
                            offenders.append(trail['TrailARN'] + ":Disabled")
                        elif eventselector['ReadWriteType'] == "All":
                            pass
                        elif eventselector['ReadWriteType'] == "WriteOnly":
                            pass
                        else:
                            result = False
                            failReason.append(
                                trail['TrailARN'] + " trail with Object-level with no logging for write events.")
                            offenders.append(trail['TrailARN'] + ":NoWrite")

                except ClientError as e:
                    # Trail from a different region
                    if e.response['Error']['Code'] == 'TrailNotFoundException':
                        pass
                    # Non-existent region
                    elif "The security token included in the request is invalid" in str(e):
                        pass
                    else:
                        print("Unknown error: " + str(e))
                        pass
    else:
        result = False
        failReason.append("CloudTrails disabled in all regions")
        offenders.append("Cloudtrails:AllRegions")

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 3.11 Ensure that Object-level logging for read events is enabled for S3 bucket (Automated)
def control_3_11(cloudtrails):
    result = True
    failReason = []
    offenders = []
    control = "3.11"
    description = "Ensure that Object-level logging for read events is enabled for S3 bucket."

    if bool(cloudtrails):
        for cloudtrail in cloudtrails:
            client = boto3.client('cloudtrail', region_name=cloudtrail, config=Config(
                connect_timeout=5, read_timeout=60, retries={'max_attempts': 20}))
            for trail in cloudtrails[cloudtrail]:
                try:
                    response = client.get_event_selectors(
                        TrailName=trail['Name'])
                    for eventselector in response['EventSelectors']:
                        if eventselector['DataResources'] == []:
                            result = False
                            failReason.append(
                                trail['TrailARN'] + " trail with Object-level logging disabled.")
                            offenders.append(trail['TrailARN'] + ":Disabled")
                        elif eventselector['ReadWriteType'] == "All":
                            pass
                        elif eventselector['ReadWriteType'] == "ReadOnly":
                            pass
                        else:
                            result = False
                            failReason.append(
                                trail['TrailARN'] + " trail with Object-level with no logging for read events.")
                            offenders.append(trail['TrailARN'] + ":NoRead")

                except ClientError as e:
                    # Trail from a different region
                    if e.response['Error']['Code'] == 'TrailNotFoundException':
                        pass
                    # Non-existent region
                    elif "The security token included in the request is invalid" in str(e):
                        pass
                    else:
                        print("Unknown error: " + str(e))
                        pass
    else:
        result = False
        failReason.append("CloudTrails disabled in all regions")
        offenders.append("Cloudtrails:AllRegions")

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# --- 4. Monitoring ---
def controls_4_X(control_num, cloudtrails):
    control_array = ["4.1", "4.2", "4.3", "4.4", "4.5", "4.6", "4.7",
                     "4.8", "4.9", "4.10", "4.11", "4.12", "4.13", "4.14", "4.15"]

    description_array = []
    description_array.append("Ensure log metric filter unauthorized api calls")
    description_array.append(
        "Ensure a log metric filter and alarm exist for Management Console sign-in without MFA")
    description_array.append(
        "Ensure a log metric filter and alarm exist for usage of \"root\" account")
    description_array.append(
        "Ensure a log metric filter and alarm exist for IAM policy changes")
    description_array.append(
        "Ensure a log metric filter and alarm exist for CloudTrail configuration changes")
    description_array.append(
        "Ensure a log metric filter and alarm exist for AWS Management Console authentication failures")
    description_array.append(
        "Ensure a log metric filter and alarm exist for disabling or scheduled deletion of customer created CMKs")
    description_array.append(
        "Ensure a log metric filter and alarm exist for S3 bucket policy changes")
    description_array.append(
        "Ensure a log metric filter and alarm exist for AWS Config configuration changes")
    description_array.append(
        "Ensure a log metric filter and alarm exist for security group changes")
    description_array.append(
        "Ensure a log metric filter and alarm exist for changes to Network Access Control Lists (NACL)")
    description_array.append(
        "Ensure a log metric filter and alarm exist for changes to network gateways")
    description_array.append(
        "Ensure a log metric filter and alarm exist for route table changes")
    description_array.append(
        "Ensure a log metric filter and alarm exist for VPC changes")
    description_array.append(
        "Ensure a log metric filter and alarm exists for AWS Organizations changes")

    patterns_array = []
    patterns_array.append(["\$\.errorCode\s*=\s*\"?\*UnauthorizedOperation(\"|\)|\s)", "\$\.errorCode\s*=\s*\"?AccessDenied\*(\"|\)|\s)",
                          "\$\.sourceIPAddress\s*!=\s*\"?\*delivery.logs.amazonaws.com(\"|\)|\s)", "\$\.eventName\s*!=\s*\"?\*HeadBucket(\"|\)|\s)"])
    patterns_array.append(["\$\.eventName\s*=\s*\"?ConsoleLogin(\"|\)|\s)", "\$\.additionalEventData\.MFAUsed\s*\!=\s*\"?Yes",
                          "\$\.userIdentity\.type\s*=\s*\"IAMUser\"|\)|\s)", "\$\.responseElements\.ConsoleLogin\s*\!=\s*\"?Success"])
    patterns_array.append(["\$\.userIdentity\.type\s*=\s*\"?Root",
                          "\$\.userIdentity\.invokedBy\s*NOT\s*EXISTS", "\$\.eventType\s*\!=\s*\"?AwsServiceEvent(\"|\)|\s)"])
    patterns_array.append(["\$\.eventName\s*=\s*\"?DeleteGroupPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteRolePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteUserPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutGroupPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutRolePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutUserPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreatePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeletePolicy(\"|\)|\s)",
                          "\$\.eventName\s*=\s*\"?CreatePolicyVersion(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeletePolicyVersion(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachRolePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachRolePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachUserPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachUserPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachGroupPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachGroupPolicy(\"|\)|\s)"])
    patterns_array.append(["\$\.eventName\s*=\s*\"?CreateTrail(\"|\)|\s)", "\$\.eventName\s*=\s*\"?UpdateTrail(\"|\)|\s)",
                          "\$\.eventName\s*=\s*\"?DeleteTrail(\"|\)|\s)", "\$\.eventName\s*=\s*\"?StartLogging(\"|\)|\s)", "\$\.eventName\s*=\s*\"?StopLogging(\"|\)|\s)"])
    patterns_array.append(["\$\.eventName\s*=\s*\"?ConsoleLogin(\"|\)|\s)",
                          "\$\.errorMessage\s*=\s*\"?Failed authentication(\"|\)|\s)"])
    patterns_array.append(["\$\.eventSource\s*=\s*\"?kms\.amazonaws\.com(\"|\)|\s)",
                          "\$\.eventName\s*=\s*\"?DisableKey(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ScheduleKeyDeletion(\"|\)|\s)"])
    patterns_array.append(["\$\.eventSource\s*=\s*\"?s3\.amazonaws\.com(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketAcl(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketCors(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutBucketLifecycle(\"|\)|\s)",
                          "\$\.eventName\s*=\s*\"?PutBucketReplication(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteBucketPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteBucketCors(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteBucketLifecycle(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteBucketReplication(\"|\)|\s)"])
    patterns_array.append(["\$\.eventSource\s*=\s*\"?config\.amazonaws\.com(\"|\)|\s)", "\$\.eventName\s*=\s*\"?StopConfigurationRecorder(\"|\)|\s)",
                          "\$\.eventName\s*=\s*\"?DeleteDeliveryChannel(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutDeliveryChannel(\"|\)|\s)", "\$\.eventName\s*=\s*\"?PutConfigurationRecorder(\"|\)|\s)"])
    patterns_array.append(["\$\.eventName\s*=\s*\"?AuthorizeSecurityGroupIngress(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AuthorizeSecurityGroupEgress(\"|\)|\s)", "\$\.eventName\s*=\s*\"?RevokeSecurityGroupIngress(\"|\)|\s)",
                          "\$\.eventName\s*=\s*\"?RevokeSecurityGroupEgress(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateSecurityGroup(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteSecurityGroup(\"|\)|\s)"])
    patterns_array.append(["\$\.eventName\s*=\s*\"?CreateNetworkAcl(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateNetworkAclEntry(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteNetworkAcl(\"|\)|\s)",
                          "\$\.eventName\s*=\s*\"?DeleteNetworkAclEntry(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ReplaceNetworkAclEntry(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ReplaceNetworkAclAssociation(\"|\)|\s)"])
    patterns_array.append(["\$\.eventName\s*=\s*\"?CreateCustomerGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteCustomerGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachInternetGateway(\"|\)|\s)",
                          "\$\.eventName\s*=\s*\"?CreateInternetGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteInternetGateway(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachInternetGateway(\"|\)|\s)"])
    patterns_array.append(["\$\.eventName\s*=\s*\"?CreateRoute(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateRouteTable(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ReplaceRoute(\"|\)|\s)",
                          "\$\.eventName\s*=\s*\"?ReplaceRouteTableAssociation(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteRouteTable(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteRoute(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DisassociateRouteTable(\"|\)|\s)"])
    patterns_array.append(["\$\.eventName\s*=\s*\"?CreateVpc(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteVpc(\"|\)|\s)", "\$\.eventName\s*=\s*\"?ModifyVpcAttribute(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AcceptVpcPeeringConnection(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateVpcPeeringConnection(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteVpcPeeringConnection(\"|\)|\s)",
                          "\$\.eventName\s*=\s*\"?RejectVpcPeeringConnection(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachClassicLinkVpc(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachClassicLinkVpc(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DisableVpcClassicLink(\"|\)|\s)", "\$\.eventName\s*=\s*\"?EnableVpcClassicLink(\"|\)|\s)"])
    patterns_array.append(["\$\.eventSource\s*=\s*\"?organizations.amazonaws.com(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AcceptHandshake(\"|\)|\s)", "\$\.eventName\s*=\s*\"?AttachPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateAccount(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreateOrganizationalUnit(\"|\)|\s)", "\$\.eventName\s*=\s*\"?CreatePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeclineHandshake(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteOrganization(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DeleteOrganizationalUnit(\"|\)|\s)",
                          "\$\.eventName\s*=\s*\"?DeletePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DetachPolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?DisablePolicyType(\"|\)|\s)", "\$\.eventName\s*=\s*\"?EnablePolicyType(\"|\)|\s)", "\$\.eventName\s*=\s*\"?InviteAccountToOrganization(\"|\)|\s)", "\$\.eventName\s*=\s*\"?LeaveOrganization(\"|\)|\s)", "\$\.eventName\s*=\s*\"?MoveAccount(\"|\)|\s)", "\$\.eventName\s*=\s*\"?RemoveAccountFromOrganization(\"|\)|\s)", "\$\.eventName\s*=\s*\"?UpdatePolicy(\"|\)|\s)", "\$\.eventName\s*=\s*\"?UpdateOrganizationalUnit(\"|\)|\s)"])

    result = True
    failReason = []
    offenders = []
    control = control_array[control_num]
    description = description_array[control_num]
    patterns = patterns_array[control_num]

    if bool(cloudtrails):
        for cloudtrail in cloudtrails:
            for trail in cloudtrails[cloudtrail]:
                try:
                    if trail['CloudWatchLogsLogGroupArn']:
                        # Get group name
                        group = re.search(
                            'log-group:(.+?):', trail['CloudWatchLogsLogGroupArn']).group(1)
                        client = boto3.client('cloudtrail', region_name=cloudtrail, config=Config(
                            connect_timeout=5, read_timeout=60, retries={'max_attempts': 20}))
                        response = client.get_event_selectors(
                            TrailName=trail['Name'])
                        for eventselector in response['EventSelectors']:
                            if eventselector['ReadWriteType'] != "All":
                                result = False
                                failReason.append(
                                    "Trail: " + trail['TrailARN'] + ":Incorrect ReadWriteType")
                                offenders.append(
                                    trail['TrailARN'] + ":Incorrect ReadWriteType")
                            if eventselector['IncludeManagementEvents'] != True:
                                result = False
                                failReason.append(
                                    "Trail: " + trail['TrailARN'] + ":IncludeManagementEvents set to False")
                                offenders.append(
                                    trail['TrailARN'] + ":IncludeManagementEvents set to False")

                        client = boto3.client('logs', region_name=cloudtrail)
                        filters = client.describe_metric_filters(
                            logGroupName=group)
                        if filters['metricFilters'] == []:
                            result = False
                            failReason.append(
                                "Trail: " + trail['TrailARN'] + ":no Metric Filters available")
                            offenders.append(
                                trail['TrailARN'] + ":noMetricFilters")
                        else:
                            for metric in filters['metricFilters']:
                                inpatterns = False
                                for pattern in patterns:
                                    if re.search(pattern, metric['filterPattern']):
                                        inpatterns = True
                                        break
                                if inpatterns == True:
                                    cwclient = boto3.client(
                                        'cloudwatch', region_name=cloudtrail)
                                    response = cwclient.describe_alarms_for_metric(
                                        MetricName=metric['metricTransformations'][0]['metricName'], Namespace=metric['metricTransformations'][0]['metricNamespace'])
                                    snsClient = boto3.client(
                                        'sns', region_name=cloudtrail)
                                    subscribers = snsClient.list_subscriptions_by_topic(
                                        TopicArn=response['MetricAlarms'][0]['AlarmActions'][0])
                                    if len(subscribers['Subscriptions']) != 0:
                                        result = True
                                    else:
                                        result = False
                                        failReason.append(
                                            "Trail: " + trail['TrailARN'] + ":wrong metric patterns: " + metric['filterPattern'])
                                        offenders.append(
                                            trail['TrailARN'] + ":wrongPatterns")
                except:
                    pass
    else:
        result = False
        failReason.append("CloudTrails disabled in all regions")
        offenders.append("Cloudtrails:AllRegions")

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# --- 5. Networking ---
# 5.1 Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports (Automated)
def control_5_1(regions):
    result = True
    failReason = []
    offenders = []
    control = "5.1"
    description = "Ensure no Network ACLs allow ingress from 0.0.0.0/0 to remote server administration ports."

    for region in regions:
        try:
            client = boto3.client('ec2', region_name=region, config=Config(
                connect_timeout=5, read_timeout=60, retries={'max_attempts': 20}))
            response = client.describe_network_acls()
            for acl in response['NetworkAcls']:
                for entry in acl['Entries']:
                    if entry['Egress'] == False and entry['RuleAction'] == "allow" and entry['CidrBlock'] == "0.0.0.0/0":
                        if entry['Protocol'] == "22" or entry['Protocol'] == "3389":
                            result = False
                            failReason.append(
                                "Region " + region + ": " + acl['NetworkAclId'] + " ACL with port " + entry['Protocol'] + " open to the Internet (0.0.0.0/0)")
                            offenders.append(
                                "Region " + region + ":ACL " + acl['NetworkAclId'] + ":Port " + entry['Protocol'])
                        elif entry['Protocol'] == "-1":
                            result = False
                            failReason.append(
                                "Region " + region + ": " + acl['NetworkAclId'] + " ACL with all ports open to the Internet (0.0.0.0/0)")
                            offenders.append(
                                "Region " + region + ":ACL " + acl['NetworkAclId'] + ":AllPorts")
        except ClientError as e:
            if e.response['Error']['Code'] == 'AuthFailure':  # Non existing regions
                pass

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 5.2 Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports (Automated)
def control_5_2(regions):
    result = True
    failReason = []
    offenders = []
    control = "5.2"
    description = "Ensure no security groups allow ingress from 0.0.0.0/0 to remote server administration ports."

    for region in regions:
        try:
            client = boto3.client('ec2', region_name=region, config=Config(
                connect_timeout=5, read_timeout=60, retries={'max_attempts': 20}))
            response = client.describe_security_groups()
            for sec_group in response['SecurityGroups']:
                if "0.0.0.0/0" in str(sec_group['IpPermissions']):
                    for rule in sec_group['IpPermissions']:
                        try:
                            if (int(rule['ToPort']) == 3389 and '0.0.0.0/0' in str(rule['IpRanges'])) or (int(rule['ToPort']) == 22 and '0.0.0.0/0' in str(rule['IpRanges'])):
                                result = False
                                failReason.append("Region " + region + ": " + sec_group['GroupId'] + " Security Group with port " + str(
                                    rule['ToPort']) + " open to the Internet (0.0.0.0/0)")
                                offenders.append(
                                    "Region " + region + ":Security Group " + sec_group['GroupId'] + ":Port " + str(rule['ToPort']))
                        except Exception as e:
                            if rule['IpProtocol'] == "-1" and '0.0.0.0/0' in str(rule['IpRanges']):
                                result = False
                                failReason.append(
                                    "Region " + region + ": " + sec_group['GroupId'] + " Security Group with all ports open to the Internet (0.0.0.0/0)")
                                offenders.append(
                                    "Region " + region + ":Security Group " + sec_group['GroupId'] + ":AllPorts")
                            else:
                                print(e)
        except ClientError as e:
            if e.response['Error']['Code'] == 'AuthFailure':  # Non existing regions
                pass

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 5.3 Ensure the default security group of every VPC restricts all traffic (Automated)
def control_5_3(regions):
    result = True
    failReason = []
    offenders = []
    control = "5.3"
    description = "Ensure the default security group of every VPC restricts all traffic"

    for region in regions:
        try:
            client = boto3.client('ec2', region_name=region, config=Config(
                connect_timeout=5, read_timeout=60, retries={'max_attempts': 20}))
            response = client.describe_security_groups(
                Filters=[{'Name': 'group-name', 'Values': ['default', ]}, ])
            for sec_group in response['SecurityGroups']:
                if sec_group['IpPermissions'] != [] or sec_group['IpPermissionsEgress'] != []:
                    result = False
                    failReason.append(
                        "Region " + region + ": " + sec_group['GroupId'] + " default security group with ingress or egress rules")
                    offenders.append(
                        "Region " + region + ":Security group " + str(sec_group['GroupId']))
        except ClientError as e:
            if e.response['Error']['Code'] == 'AuthFailure':  # Non existing regions
                pass

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# 5.4 Ensure routing tables for VPC peering are "least access" (Manual)
def control_5_4(regions):
    result = True
    failReason = []
    offenders = []
    control = "5.4"
    description = "Ensure routing tables for VPC peering are \"least access\"."

    for region in regions:
        try:
            client = boto3.client('ec2', region_name=region, config=Config(
                connect_timeout=5, read_timeout=60, retries={'max_attempts': 20}))
            response = client.describe_route_tables()
            for table in response['RouteTables']:
                for route in table['Routes']:
                    try:
                        if route['VpcPeeringConnectionId']:
                            if int(route['DestinationCidrBlock'].split("/", 1)[1]) < 24:
                                result = False
                                failReason.append(
                                    "Region " + region + ": Large CIDR block routed to peer on routing table " + table['RouteTableId'] + ", please investigate")
                                offenders.append(
                                    "Region " + region + " : " + table['RouteTableId'])
                    except Exception as e:
                        if "VpcPeeringConnectionId" in str(e):
                            pass
                        else:
                            print("Unexpected error: " + str(e))

        except ClientError as e:
            if e.response['Error']['Code'] == 'AuthFailure':  # Non existing regions
                pass

    return {'Result': result, 'failReason': failReason, 'Offenders': offenders, 'Description': description, 'ControlId': control}

# ------------------


def run_CIS_checks1(cred_report, password_policy, region_list):
    """
    Checks CIS lvl 1 (IAM).
    Returns: list
    """
    control = []
    control.append(control_1_1())
    increment_progress()  # Manual
    control.append(control_1_2())
    increment_progress()  # Manual
    control.append(control_1_3())
    increment_progress()  # Manual#
    control.append(control_1_4(cred_report))
    increment_progress()
    control.append(control_1_5())
    increment_progress()
    control.append(control_1_6())
    increment_progress()
    control.append(control_1_7(cred_report))
    increment_progress()
    control.append(control_1_8(password_policy))
    increment_progress()
    control.append(control_1_9(password_policy))
    increment_progress()
    control.append(control_1_10(cred_report))
    increment_progress()
    control.append(control_1_11())# Not developed yet
    increment_progress()  
    control.append(control_1_12(cred_report))
    increment_progress()
    control.append(control_1_13())
    increment_progress()
    control.append(control_1_14(cred_report))
    increment_progress()
    control.append(control_1_15())
    increment_progress()
    control.append(control_1_16())
    increment_progress()
    control.append(control_1_17())
    increment_progress()
    control.append(control_1_18(region_list))
    increment_progress()
    control.append(control_1_19())
    increment_progress()
    control.append(control_1_20())
    increment_progress()
    control.append(control_1_21(region_list))
    increment_progress()
    control.append(control_1_22()) # Not developed/Manual
    increment_progress() 
    return control


def run_CIS_checks2(region_list):
    """
    Checks CIS lvl 2 (Storage).
    Returns: list
    """
    control = []
    control.append(control_2_1_1())
    increment_progress()
    control.append(control_2_1_2())
    increment_progress()
    control.append(control_2_2_1(region_list))
    increment_progress()

    return control


def run_CIS_checks3(region_list, cloudtrails):
    """
    Checks CIS lvl 3 (Logging).
    Returns: list
    """
    control = []
    control.append(control_3_1(cloudtrails))
    increment_progress()
    control.append(control_3_2(cloudtrails))
    increment_progress()
    control.append(control_3_3(cloudtrails))
    increment_progress()
    control.append(control_3_4(cloudtrails))
    increment_progress()
    control.append(control_3_5(region_list))
    increment_progress()
    control.append(control_3_6(cloudtrails))
    increment_progress()
    control.append(control_3_7(cloudtrails))
    increment_progress()
    control.append(control_3_8(region_list))
    increment_progress()
    control.append(control_3_9(region_list))
    increment_progress()
    control.append(control_3_10(cloudtrails))
    increment_progress()
    control.append(control_3_11(cloudtrails))
    increment_progress()
    return control


def run_CIS_checks4(cloudtrails):
    """
    Checks CIS lvl 4 (Monitoring).
    Returns: list
    """
    control = []
    for i in range(0, 15):  # Controls 4.1 to 4.15
        control.append(controls_4_X(i, cloudtrails))
        increment_progress()
    return control


def run_CIS_checks5(region_list):
    """
    Checks CIS lvl 5 (Networking).
    Returns: list
    """
    control = []
    control.append(control_5_1(region_list))# Testing with port 3389 and 22. Add more admin ports
    increment_progress()
    control.append(control_5_2(region_list))# Testing with port 3389 and 22. Add more admin ports
    increment_progress()
    control.append(control_5_3(region_list))
    increment_progress()
    control.append(control_5_4(region_list))
    increment_progress()
    return control


def show_results(tittle, controls, result_type):
    """
    Prints CIS checks results or issue suggestions.
    Returns: 0 = OK, -1 = error
    """
    line = "-" * len(tittle)
    print(line)
    print(tittle)
    print(line)

    if result_type == "cis":
        for control in controls:
            if control['Result'] == False:
                print(Style.BRIGHT + Fore.RED +
                      "[" + control['ControlId'] + "] " + control['Description'])
                for reason in control['failReason']:
                    print(Fore.RED + "\t- " + reason)
                # print()
                # for offender in control['Offenders']:
                #     print(Fore.RED + "\t- " + offender)
            elif control['Result'] == True:
                print(Style.BRIGHT + Fore.GREEN +
                      "[" + control['ControlId'] + "] " + control['Description'])
            else:
                print(Style.BRIGHT + Fore.YELLOW +
                      "[" + control['ControlId'] + "] " + control['Description'])
                for reason in control['failReason']:
                    print(Style.BRIGHT + Fore.YELLOW + "\t- " + reason)
        print(Style.RESET_ALL)
    elif result_type == "suggest":
        for issues in controls:
            if issues != []:
                for issue in issues:
                    if issue['Result'] == True:
                        print()
                        print(Style.BRIGHT + Fore.GREEN + issue['Name'])
                        for reason in issue['total_reasons']:
                            print(Style.BRIGHT + Fore.YELLOW + "\t- " + reason)
                        print(Style.BRIGHT + Fore.YELLOW + "INSTANCES: " +
                              str(issue['total_offenders']) + Style.RESET_ALL)

    else:
        print(Style.BRIGHT + Fore.RED + "[ERROR] Wrong result type.")
        return -1
    return 0


def check_issue(name, checks, controls):
    """
    Checks if a certain RWT issue needs to be suggested.
    Returns: list
    """
    rwt = []
    is_issue = False
    total_reasons = []
    total_offenders = []

    for check in checks:
        for control in controls:
            if control != []:
                for res in control:
                    if res['ControlId'] == check:
                        if res['Result'] == False:
                            is_issue = True
                            for reason in res['failReason']:
                                total_reasons.append(reason)
                            for offender in res['Offenders']:
                                total_offenders.append(offender)
    rwt.append({'Name': name, 'Result': is_issue,
               'total_reasons': total_reasons, 'total_offenders': total_offenders})

    return rwt


def suggest_issues(controls):
    suggestions = []
    filepath = 'issues.cfg'
    with open(filepath) as fp:
        line = fp.readline()

        while line:
            issue = line.split('=')[0]
            issue_checks = (line.split('=')[1]).split(',')
            suggestions.append(check_issue(issue, issue_checks, controls))

            line = fp.readline()

    show_results("--- ISSUE SUGGESTIONS ---", suggestions, "suggest")

    return


def verify_account():
    try:
        client = boto3.client('sts')
        response = client.get_caller_identity()
        print("Using the following credentials to test:")
        print("Account: " + response['Account'])
        print("Arn: " + response['Arn'])
        print("")
    except Exception as e:
        if "Unable to locate credentials" in str(e):
            print("ERROR: " + str(e))
            print("Please, verify your ~/.aws/ folder.")
            sys.exit(-1)


if __name__ == '__main__':
    profile_name = ''
    suggest = False
    cis = True
    try:
        opts, args = getopt.getopt(sys.argv[1:], "p:h", [
                                   "profile=", "help", "suggest", "cis", "all"])
    except getopt.GetoptError:
        print("Error: Illegal option\n")
        print("---Usage---")
        print('Run without parameters to use default profile:')
        print("python " + sys.argv[0] + "\n")
        print("Use -p or --profile to specify a specific profile:")
        print("python " + sys.argv[0] + ' -p <profile>')
        print("Use --cis to get a detailed list of CIS Benchmark v1.3.0 checks")
        print("python " + sys.argv[0] + ' --cis')
        print("Use --suggest to get suggestions on which issues should you use on your report")
        print("python " + sys.argv[0] + ' --suggest')
        print("Use --all to get get both --suggest and --cis")
        print("python " + sys.argv[0] + ' --all')
        sys.exit(-1)

    # Parameter options
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            print("---Help---")
            print('Run without parameters to use default profile:')
            print("python " + sys.argv[0] + "\n")
            print("Use -p or --profile to specify a specific profile:")
            print("python " + sys.argv[0] + ' -p <profile>')
            sys.exit()
        elif opt in ("-p", "--profile"):
            profile_name = arg
        elif opt in ("--suggest"):
            suggest = True
            cis = False
        elif opt in ("--cis"):
            cis = True
        elif opt in ("--all"):
            suggest = True
            cis = True

    banner()
    verify_account()
    if not profile_name == "":  # Verify that the profile exist
        try:
            boto3.setup_default_session(profile_name=profile_name)
            # Update globals with new profile. Custom retry configuration to avoid throttling errors.
            IAM_CLIENT = boto3.client('iam', config=Config(
                connect_timeout=5, read_timeout=60, retries={'max_attempts': 20}))
            S3_CLIENT = boto3.client('s3', config=Config(
                connect_timeout=5, read_timeout=60, retries={'max_attempts': 20}))
        except ClientError as e:
            if "could not be found" in str(e):
                print("Error: " + str(e))
                print("Please verify your profile name.")
                sys.exit(-1)
            else:
                print("Unexpected error: " + str(e))
                sys.exit(-1)

    increment_progress()
    region_list, cred_report, password_policy, cloudtrails = get_aws_info()
    control1 = run_CIS_checks1(cred_report, password_policy, region_list)
    control2 = run_CIS_checks2(region_list)
    control3 = run_CIS_checks3(region_list, cloudtrails)
    control4 = run_CIS_checks4(cloudtrails)
    control5 = run_CIS_checks5(region_list)
    print()

    if cis:
        show_results("--- 1. Identity and Access Management ---", control1, "cis")
        show_results("--- 2. Storage ---", control2, "cis")
        show_results("--- 3. Logging ---", control3, "cis")
        show_results("--- 4. Monitoring ---", control4, "cis")
        show_results("--- 5. Networking ---", control5, "cis")

    if suggest:
        controls = []
        controls.append(control1)
        controls.append(control2)
        controls.append(control3)
        controls.append(control4)
        controls.append(control5)
        suggest_issues(controls)
