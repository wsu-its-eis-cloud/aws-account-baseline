# aws-account-baseline
This tool configures AWS accounts according to a standard baseline set by WSU ITS, and includes the following core components:

* Default IAM policies, roles, and groups.
* Default AWS Config, Guard Duty, and Security Hub configurations and reporting.
* Default EBS Encryption
* Automatic age-out of Security Group entries.
* Sets password complexity, and requires MFA.
* Removes default VPC's that exist at account creation.
* Disables STS endpoints and regions outside of US-WEST-2
* And more.

# instructions

To apply this baseline to a new AWS account, perform the following:

* Perform a git pull
* Run setup.ps1 as administrator
* Use https://github.com/wsu-its-eis-cloud/aws-api-session-management to generate a secure session.
* Run main.ps1 -accountName <wsu-area-unit-function>
* A zip of the transcript and outputs will be created. Store these in a secure location, and complete the generated checklist for new account configuration.
