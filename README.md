# Glacier Backup

This is a simple backup script which recursively mirrors files from a local directory in a vault on an Amazon Glacier instance. It has the capability to download an inventory of the vault (which takes hours due to the nature of Glacier) and maintain a local database of all files and their status.

Configuration values are entered into the config.txt file, and glacier_backup.py manages the rest.

Credentials (KEY, SECRET, region) should be configured using the AWS CLI tools.
