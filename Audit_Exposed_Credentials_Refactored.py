#!/usr/bin/env python
# coding: utf-8

import requests
import pandas as pd
from datetime import datetime
import os
import sys

#Check if the accounts password has not been changed since the breach date
    #Returns True if password hasn't been changed thus requiring a reset
    #Returns False if password has already been changed
    #input types are strings
def account_password_not_changed_since_breach_date(directory_account_last_password_change_date,credential_breach_date_str):
    #Construct DateTimeObject for breach date
    breach_date_dt_object=datetime(int(credential_breach_date_str.split('/')[2]),int(credential_breach_date_str.split('/')[0]),int(credential_breach_date_str.split('/')[1]))
    last_password_changd_dt_object=datetime(int(directory_account_last_password_change_date.get('lastPasswordChangeDateTime')[0:4]),int(directory_account_last_password_change_date.get('lastPasswordChangeDateTime')[5:7]),int(directory_account_last_password_change_date.get('lastPasswordChangeDateTime')[8:10]))
    #Perform boolean comparison to determine if account password should be changed
    return last_password_changd_dt_object<= breach_date_dt_object

#Function that adds the directory account's UPN, email, and recommendations to the output report dictionary object
def add_upn_to_output_report(output_report_dictionary,user_object_within_directory,reason):
    output_report_dictionary.get('account_UPN').append(user_object_within_directory.get('userPrincipalName').lower().replace(' ',''))
    if user_object_within_directory.get('mail')!=None: 
        output_report_dictionary.get('email_address').append(user_object_within_directory.get('mail').lower().replace(' ',''))
    else:
        output_report_dictionary.get('email_address').append(None)
    output_report_dictionary.get("recommended_action").append(reason)

#Function that will ingest the workflow's input and normalize input for workflow run
    #workflow_input_format is a str that specifies the path to the input CSV
    #If a non valid path is specified, the workflow will exit
    #Returns a tuple indicating (list_of_account_IDs_within_breach_dataset,breach_date_for_respective_account)
def process_workflow_input(path_to_input_CSV):
    if not os.path.exists(path_to_input_CSV):
        print("Invalid path to input CSV\nTerminating workflow")
        sys.exit(0)
    #Load list of account identifiers from the breach dataset
    list_of_account_identifiers_unclean=pd.read_csv(filepath_or_buffer=path_to_input_CSV)['UserName'].tolist()
    #Sanatize the input account identifiers
    list_of_account_identifiers=[]
    for unclean_account_identifier in list_of_account_identifiers_unclean:
        if unclean_account_identifier!=None and type(unclean_account_identifier)==str:
            list_of_account_identifiers.append(unclean_account_identifier.lower().replace(' ' ,''))
        elif unclean_account_identifier!=None and type(unclean_account_identifier)==int:
            list_of_account_identifiers.append(str(unclean_account_identifier).lower().replace(' ' ,''))
    #Load list of each account identifier's respective breach date
    list_of_account_identifier_breach_date=pd.read_csv(filepath_or_buffer=path_to_input_CSV)["Breach_Date"].to_list()
    #Sanatize breach date format
    list_of_account_identifier_breach_date=[breach_date.lower().replace(' ','')  for breach_date in list_of_account_identifier_breach_date if type(breach_date)==str]
    print("Successfully read in workflow input CSV")
    return tuple([list_of_account_identifiers,list_of_account_identifier_breach_date])

print("Reading workflow input CSV")
cleaned_workflow_input_tuple=process_workflow_input('/Users/josephbrennan/pythonscripts/breachdataset/breach_data_set.csv')
list_of_account_identifiers=cleaned_workflow_input_tuple[0]
list_of_account_identifier_breach_date=cleaned_workflow_input_tuple[1]

#Create a list of dictionaries where each dictionary contains the breached account identifier and the account's respective breach date
list_of_cleaned_account_identifiers_within_the_breach_and_respective_breach_date=[]
index=0
#Combine breach account identifier strings with the account identifier's respective breach date
for cleaned_account_identifier in list_of_account_identifiers:
    map_of_account_identifiers_and_respective_breach_date={"account_identifier_within_breach_dataset":cleaned_account_identifier,"breach_date":list_of_account_identifier_breach_date[index]}
    list_of_cleaned_account_identifiers_within_the_breach_and_respective_breach_date.append(map_of_account_identifiers_and_respective_breach_date)
    index+=1

print("Obtaining OAuthBearer Token")
#Obtain Bearer Token
request_for_oauth_Token_headers={"client_id":"","client_secret":"","resource":"https://graph.microsoft.com","grant_type":"client_credentials"}
json_token=requests.post(url="https://login.microsoftonline.com/8e1d2836-0590-44ba-a737-5761471408d8/oauth2/token",data=request_for_oauth_Token_headers).json().get('access_token')


dictionary_for_user_requests={"Authorization":f"Bearer {json_token}"}
print("Bearer Token obtained \n")
#Obtain all the enabled member accounts within the directory
    #Within Entra, you can't reset the password for an account that's disabled and tenant has many many old disabled accounts
    #Member accounts only because we don't manage guest account credentials. Seperate conversation with IAM is requested for guest accounts
enabled_member_accounts_within_directory=requests.get(url="https://graph.microsoft.com/v1.0/users",headers=dictionary_for_user_requests,params={"$filter": "accountEnabled eq true and userType eq 'member'","$select":"userPrincipalName,id,mail,mailNickname,employeeID,onPremisesSamAccountName,onPremisesUserPrincipalName,onPremisesImmutableId,onPremisesSecurityIdentifier,proxyAddresses,accountEnabled,imAddresses,otherEmails,lastPasswordChangeDateTime,otherMails,onPremisesDomainName,userType"}).json().get('value')

#Create 
    #Set of all UPN domains within the tenant for enabled member accounts
    #Set of all email domains within the tenant for enabled member accounts
    #Dictionary directory_account_UPN:set of emails valid for that directory account
set_of_UPN_domains=set()
set_of_email_domains=set()
account_UPN_to_email_map={}
for object_within_directory in enabled_member_accounts_within_directory:
    #Check if the accounts password has not been changed since the breach date
    if object_within_directory.get('userPrincipalName').lower().replace(' ','') not in account_UPN_to_email_map.keys():
        account_UPN_to_email_map[f"{object_within_directory.get('userPrincipalName').lower().replace(' ','')}"]=set()
    #Add the Entra ID UPN domain to list of UPN domains
    if  object_within_directory.get('userPrincipalName')!=None and  "@" in object_within_directory.get('userPrincipalName'):
        set_of_UPN_domains.add(object_within_directory.get('userPrincipalName').split('@')[1].lower().replace(' ',''))
    #Add the ProxyAddresses to list of email domains
    if object_within_directory.get('proxyAddresses')!=None and len(object_within_directory.get('proxyAddresses'))!=0:
        for email in object_within_directory.get('proxyAddresses'):
            if  email!=None and   "@" in  email:
                set_of_email_domains.add(email.split("@")[1].lower().replace(' ',''))
            if email !=None and account_UPN_to_email_map.get(f"{object_within_directory.get('userPrincipalName').lower().replace(' ','')}")!=None:
                account_UPN_to_email_map.get(f"{object_within_directory.get('userPrincipalName').lower().replace(' ','')}").add(email.lower().replace(' ',''))
                account_UPN_to_email_map.get(f"{object_within_directory.get('userPrincipalName').lower().replace(' ','')}").add(email[5:].lower().replace(' ',''))
    #Add the onPremisesUPN to list of UPN domains
    if object_within_directory.get('onPremisesUserPrincipalName')!=None and "@" in object_within_directory.get('onPremisesUserPrincipalName'):
        set_of_UPN_domains.add(object_within_directory.get('onPremisesUserPrincipalName').split('@')[1].lower().replace(' ',''))
    #Add primaryEmail domain to list of email domains
    if object_within_directory.get('mail')!=None and "@" in object_within_directory.get('mail'):
        set_of_email_domains.add(object_within_directory.get('mail').split('@')[1].lower().replace(' ',''))
    #Add primaryEmail to UPN -> set of emails
    if account_UPN_to_email_map.get(f"{object_within_directory.get('userPrincipalName').lower().replace(' ','')}")!=None and object_within_directory.get('mail')!=None:
        account_UPN_to_email_map.get(f"{object_within_directory.get('userPrincipalName').lower().replace(' ','')}").add(object_within_directory.get('mail').lower().replace(' ',''))
    #All OtherMail domains to list of email domains
    if object_within_directory.get('otherMails')!=None and len(object_within_directory.get('otherMails'))!=0:
        for mail in object_within_directory.get('otherMails'):
            if mail!=None and "@" in mail:
                set_of_email_domains.add(mail.split('@')[1].lower().replace(' ',''))
            if mail !=None and account_UPN_to_email_map.get(f"{object_within_directory.get('userPrincipalName').lower().replace(' ','')}")!=None:
                account_UPN_to_email_map.get(f"{object_within_directory.get('userPrincipalName').lower().replace(' ','')}").add(mail.lower().replace(' ',''))
    #Add IMAddresses domains to list of email domains
    if object_within_directory.get('imAddresses') !=None and len(object_within_directory.get('imAddresses'))!=0:
        for im_adddress in object_within_directory.get('imAddresses'):
            if im_adddress!=None and  "@" in  im_adddress:
                set_of_email_domains.add(im_adddress.split("@")[1].lower().replace(' ' ,''))
            if im_adddress!=None and account_UPN_to_email_map.get(f"{object_within_directory.get('userPrincipalName').lower().replace(' ','')}")!=None:
                account_UPN_to_email_map.get(f"{object_within_directory.get('userPrincipalName').lower().replace(' ','')}").add(im_adddress.lower().replace(' ',''))
    #Add onPremisesDomainName to list of UPN domains
    if object_within_directory.get("onPremisesDomainName") != None:
        set_of_UPN_domains.add(object_within_directory.get("onPremisesDomainName").lower().replace(' ',''))
                            
#print(f"The number of accounts that will be analyzed for password rotation is {len(enabled_member_accounts_within_directory)}")
#print()
#print(f"The length of the dictionary is {len(account_UPN_to_email_map.keys())}")
#print()
#print(f"The number of UPN domains is {len(set_of_UPN_domains)}")
#print()
#print(f"The list of UPN domains are {set_of_UPN_domains}")
#print()
#print(f"The list of email domains are {set_of_email_domains}")
#print()
#print(f"The number of email domains with the tenant: {len(set_of_email_domains)}")

#print()
print("Begin the first state of processing")
print("Process the breach dataset against the directory")

#Create dictionary for output report
output_report_dictionary={"account_UPN":[],"email_address":[],"recommended_action":[]}

#Iterate through each account identifier in the breach datset
for account_id_within_breach_dataset in list_of_cleaned_account_identifiers_within_the_breach_and_respective_breach_date:
    #Check each breach dataset account identifier against in scope directory accounts
    for user_object_within_directory in enabled_member_accounts_within_directory:
        #Gather all the emails for the current directory account
        set_of_emails_for_current_account=set()
        if user_object_within_directory.get("mail")!=None:
            set_of_emails_for_current_account.add(user_object_within_directory.get("mail").lower().replace(' ',''))
        for current_proxy_email in user_object_within_directory.get('proxyAddresses'):
            set_of_emails_for_current_account.add(current_proxy_email.lower().replace(' ',''))
            set_of_emails_for_current_account.add(current_proxy_email[5:].lower().replace(' ',''))
        for current_other_email in user_object_within_directory.get('otherMails'):
            set_of_emails_for_current_account.add(current_other_email.lower().replace(' ',''))
        for current_im_address in user_object_within_directory.get("imAddresses"):
            set_of_emails_for_current_account.add(current_im_address.lower().replace(' ',''))
        #Check 1: See if the account identifier within the breach dataset matches an email for a directory account
        if account_id_within_breach_dataset.get('account_identifier_within_breach_dataset') in set_of_emails_for_current_account and user_object_within_directory.get('userPrincipalName').lower().replace(' ','') not in output_report_dictionary.get('account_UPN') and  account_password_not_changed_since_breach_date(user_object_within_directory,account_id_within_breach_dataset.get('breach_date')):
            add_upn_to_output_report(output_report_dictionary,user_object_within_directory,"Password Rotation: This account's email was found within a data breach")
        #Check 2: See if the account identifier within the breach dataset matches a UPN for an account within Entra tenant
        elif user_object_within_directory.get('userPrincipalName')!=None and account_id_within_breach_dataset.get('account_identifier_within_breach_dataset') == user_object_within_directory.get('userPrincipalName').lower().replace(' ','') and user_object_within_directory.get('userPrincipalName').lower().replace(' ','') not in output_report_dictionary.get('account_UPN') and  account_password_not_changed_since_breach_date(user_object_within_directory,account_id_within_breach_dataset.get('breach_date')):
            add_upn_to_output_report(output_report_dictionary,user_object_within_directory,"""Password Rotation: This account's UPN was found within a data breach""")
        #Check 3. See if the account identifier within the breach dataset matches the objectID for an account within the Entra directory
        elif user_object_within_directory.get('id')!=None and account_id_within_breach_dataset.get('account_identifier_within_breach_dataset') == user_object_within_directory.get('id').lower().replace(' ','') and user_object_within_directory.get('userPrincipalName').lower().replace(' ','') not in output_report_dictionary.get('account_UPN') and  account_password_not_changed_since_breach_date(user_object_within_directory,account_id_within_breach_dataset.get('breach_date')):
            add_upn_to_output_report(output_report_dictionary,user_object_within_directory,"Password Rotation: This account's objectID was found within a data breach")
        #Check 4. See if the account identifier within the breach dataset matches the Mail nickname for an account within the Entra directory
        elif user_object_within_directory.get('mailNickname') != None and account_id_within_breach_dataset.get('account_identifier_within_breach_dataset')==user_object_within_directory.get('mailNickname').lower().replace(' ','') and user_object_within_directory.get('userPrincipalName').lower().replace(' ','') not in output_report_dictionary.get('account_UPN') and  account_password_not_changed_since_breach_date(user_object_within_directory,account_id_within_breach_dataset.get('breach_date')):
            add_upn_to_output_report(output_report_dictionary,user_object_within_directory,"Password Rotation: This account's mail Nickname was found within a data breach")
        #Check 5: See if the account identifier within the breach dataset matches the employeeid for an account within the Entra directory
        elif user_object_within_directory.get('employeeId')!=None and account_id_within_breach_dataset.get('account_identifier_within_breach_dataset')==user_object_within_directory.get('employeeId').lower().replace(' ','') and user_object_within_directory.get('userPrincipalName').lower().replace(' ', '') not in output_report_dictionary.get('account_UPN') and  account_password_not_changed_since_breach_date(user_object_within_directory,account_id_within_breach_dataset.get('breach_date')): 
            add_upn_to_output_report(output_report_dictionary,user_object_within_directory,"Password Rotation: This account's employeeid was found within a data breach")
        #Check 6: See if the account identifier within the breach dataset matches the Directory Sync'd (on-Prem) SAM name
        elif user_object_within_directory.get('onPremisesSamAccountName')!=None and account_id_within_breach_dataset.get('account_identifier_within_breach_dataset')==user_object_within_directory.get('onPremisesSamAccountName').lower().replace(' ','') and user_object_within_directory.get('userPrincipalName').lower().replace(' ','') not in output_report_dictionary.get('account_UPN') and  account_password_not_changed_since_breach_date(user_object_within_directory,account_id_within_breach_dataset.get('breach_date')):
            add_upn_to_output_report(output_report_dictionary,user_object_within_directory,"Password Rotation: This account's Directory Sync'd (on-Prem) SAM name  was found within a data breach")
        #Check 7: See if the account identifiers within the breach dataset matches the Directory Sync'd (on-Prem) UPN
        elif  user_object_within_directory.get('onPremisesUserPrincipalName')!=None and account_id_within_breach_dataset.get('account_identifier_within_breach_dataset')==user_object_within_directory.get('onPremisesUserPrincipalName').lower().replace(' ','') and user_object_within_directory.get('userPrincipalName').lower().replace(' ','') not in output_report_dictionary.get('account_UPN') and  account_password_not_changed_since_breach_date(user_object_within_directory,account_id_within_breach_dataset.get('breach_date')):
            add_upn_to_output_report(output_report_dictionary,user_object_within_directory,"Password Rotation: This account's Directory Sync'd (on-Prem) UPN was found within a data breach")
        #Check 8. See if the account identifier within the breach dataset matches the Directory Sync'd (on-Prem) ImmutableID:
        elif  user_object_within_directory.get('onPremisesImmutableId')!=None and account_id_within_breach_dataset.get('account_identifier_within_breach_dataset')==user_object_within_directory.get('onPremisesImmutableId').lower().replace(' ','') and user_object_within_directory.get('userPrincipalName').lower().replace(' ','') not in output_report_dictionary.get('account_UPN') and  account_password_not_changed_since_breach_date(user_object_within_directory,account_id_within_breach_dataset.get('breach_date')):
            add_upn_to_output_report(output_report_dictionary,user_object_within_directory,"Password Rotation: This account's Directory Sync'd (on-Prem) ImmutableID was found within a data breach")
        #Check 9: See if the account identifier within the breach dataset matches the Directory Sync'd (on-Prem) SID for an account within the Entra tenant
        elif user_object_within_directory.get('onPremisesSecurityIdentifier')!=None and account_id_within_breach_dataset.get('account_identifier_within_breach_dataset')==user_object_within_directory.get('onPremisesSecurityIdentifier').lower().replace(' ','') and user_object_within_directory.get('userPrincipalName').lower().replace(' ','') not in output_report_dictionary.get('account_UPN') and  account_password_not_changed_since_breach_date(user_object_within_directory,account_id_within_breach_dataset.get('breach_date')):
            add_upn_to_output_report(output_report_dictionary,user_object_within_directory,"Password Rotation: This account's Directory Sync'd (on-Prem) SID was found within a data breach")
        #Check 10: See if the account identifier prefix within the breach dataset is an email address and whose prefix (before @) matches the account format
        elif user_object_within_directory.get('mailNickname')!=None and "@" in account_id_within_breach_dataset.get('account_identifier_within_breach_dataset') and account_id_within_breach_dataset.get('account_identifier_within_breach_dataset').split('@')[0] ==user_object_within_directory.get('mailNickname').lower().replace(' ','') and user_object_within_directory.get('userPrincipalName').lower().replace(' ','') not in output_report_dictionary.get('account_UPN') and  account_password_not_changed_since_breach_date(user_object_within_directory,account_id_within_breach_dataset.get('breach_date')):
            add_upn_to_output_report(output_report_dictionary,user_object_within_directory,"Password Rotation: This account's 'a' account Identifier was found within a data breach")
        #Check 11: See if the account identifier prefix within the breach dataset matches an employeeID for an account within the Entra tenant
        elif user_object_within_directory.get("employeeId")!=None and "@" in account_id_within_breach_dataset.get('account_identifier_within_breach_dataset') and account_id_within_breach_dataset.get('account_identifier_within_breach_dataset').split('@')[0] == user_object_within_directory.get("employeeId").lower().replace(' ','') and user_object_within_directory.get('userPrincipalName').lower().replace(' ','') not in output_report_dictionary.get('account_UPN') and  account_password_not_changed_since_breach_date(user_object_within_directory,account_id_within_breach_dataset.get('breach_date')):
            add_upn_to_output_report(output_report_dictionary,user_object_within_directory,"Password Rotation: This account's EmployeeID was found within a data breach")
            
print("First state of processing complete \n")

#Begin the 2nd stage of processing. 
print("Begin the second stage of processing \n")

print("Begin to process the UPN permutations ")
#Check each breached account identifier + each possible UPN domain against UPNs of enabled+member directory accounts whose password hasn't changed since the breach date
for account_id_within_breach_dataset in list_of_cleaned_account_identifiers_within_the_breach_and_respective_breach_date:
    for unique_UPN_Domain in set_of_UPN_domains:
        for user_object_within_directory in enabled_member_accounts_within_directory:
            if "@" in account_id_within_breach_dataset.get('account_identifier_within_breach_dataset') and ((user_object_within_directory.get('userPrincipalName')!=None and   f"{account_id_within_breach_dataset.get('account_identifier_within_breach_dataset').split('@')[0]}@{unique_UPN_Domain}" == user_object_within_directory.get('userPrincipalName').lower().replace(' ','')) or    ( user_object_within_directory.get('onPremisesUserPrincipalName')!=None and f"{account_id_within_breach_dataset.get('account_identifier_within_breach_dataset').split('@')[0]}@{unique_UPN_Domain}" == user_object_within_directory.get('onPremisesUserPrincipalName').lower().replace(' ','')))  and user_object_within_directory.get("userPrincipalName").lower().replace(' ','')  not in output_report_dictionary.get('account_UPN') and  account_password_not_changed_since_breach_date(user_object_within_directory,account_id_within_breach_dataset.get('breach_date')):
                add_upn_to_output_report(output_report_dictionary,user_object_within_directory,"Password Rotation: A possible permutation of this account's UPN  was found within a data breach")
                
print("Begin to process the email permutations")
#Check each breached account identifier + each possible email domain against all the possible emails of enabled+member accounts with the directory
for account_id_within_breach_dataset in list_of_cleaned_account_identifiers_within_the_breach_and_respective_breach_date:
    for email_domain in set_of_email_domains:
        for user_object_within_directory in enabled_member_accounts_within_directory:
            if  "@" in account_id_within_breach_dataset.get('account_identifier_within_breach_dataset') and f"{account_id_within_breach_dataset.get('account_identifier_within_breach_dataset').split("@")[0]}@{email_domain}" in  account_UPN_to_email_map.get(user_object_within_directory.get('userPrincipalName').lower().replace(' ','')) and user_object_within_directory.get('userPrincipalName').lower().replace(' ','') not in output_report_dictionary.get('account_UPN')  and  account_password_not_changed_since_breach_date(user_object_within_directory,account_id_within_breach_dataset.get('breach_date')):
                add_upn_to_output_report(output_report_dictionary,user_object_within_directory,"""Password Rotation: A Permuation of this account's email was found within a data breach""")
print("Processing is Complete")
#Construct the df that will be outputted as the script's report
df=pd.DataFrame.from_dict(data=output_report_dictionary,orient="columns")

#Output the report
if os.path.exists("/Users/josephbrennan/Desktop/AuditBreachedCredentialOutputReports/"): 
    df.to_csv(path_or_buf=f"/Users/josephbrennan/Desktop/AuditBreachedCredentialOutputReports/Breached_Credential_Analysis_Output_Report_{datetime.now().strftime("%Y-%m-%d_%H_%M.%S")}.csv",columns=["account_UPN","email_address","recommended_action"],index=False)
else:
    os.mkdir("/Users/josephbrennan/Desktop/AuditBreachedCredentialOutputReports/")    
    df.to_csv(path_or_buf=f"/Users/josephbrennan/Desktop/AuditBreachedCredentialOutputReports/Breached_Credential_Analysis_Output_Report_{datetime.now().strftime("%Y-%m-%d_%H_%M.%S")}.csv",columns=["account_UPN","email_address","recommended_action"],index=False)
