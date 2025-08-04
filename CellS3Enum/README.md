**CellS3Enum**

CellS3Enum.py is a S3 bucket enumerator python script that leverages AT command on a Quectel cell module via serialconnection for access to cloud for enumerating

This has not been tested with all Quectel cell modules and is considered a proof of concept tool and should be used with caution

**Usage:** python3 CellS3Enum.py --bucketnames {bucket or file} --wordlist {object list} [options]

**Example:**
  python3 CellS3Enum.py     --bucketnames bucketnames.txt     --wordlist wordlist.txt     --extensions txt json html     --s3-endpoint s3.us-east-1.amazonaws.com     --serial-port /dev/ttyUSB0     --assume-on

**This probes URLs like:**

  https://<bucket>.s3.us-east-1.amazonaws.com/<object>.<ext>

