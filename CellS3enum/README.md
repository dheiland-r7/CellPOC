**CellS3Enum2**

CellS3Enum2.py is an S3 bucket enumerator Python script that leverages AT commands on a Quectel cell module via serial connection.

The script has two modes. It can check whether bucket names exist, or it can look for files inside buckets using a wordlist.

Tested on a Quectel EG91. This has not been tested with all Quectel cell modules and is considered a proof of concept tool.

**Usage:** python3 CellS3Enum2.py --bucketnames <bucketname or bucketnames file> --wordlist <file with filenames> [options]

Files containing bucket names or filenames should be one entry per line. Filenames in the wordlist should not include the extension, use --extensions to add desired extension(s).

Running the script with no flags prints the list of flags. Use --interactive for guided setup that prompts you for the required information.

**Example (find buckets):**
  python3 CellS3Enum2.py --bucketnames bucketnames.txt --find-bucket --region us-east-1 --serial-port /dev/ttyUSB0 --assume-on

**Example (find files in buckets):**
  python3 CellS3Enum2.py --bucketnames bucketnames.txt --wordlist filenames.txt --extensions txt json html --region us-east-1 --serial-port /dev/ttyUSB0 --assume-on

**This probes URLs like:**
  https://<bucketname>.s3.us-east-1.amazonaws.com/<filename>.<ext>

File probes ask for only the first byte by default to increase speed. Use --download-dir to save any file that returns HTTP 200 to a local file, or --read-body to print part of the body to the terminal. 

Bucket names that do not follow AWS naming rules are skipped before the scan starts.

Results are written to two files with a timestamp in the name, a .jsonl stream written as the scan runs and a .csv summary written at the end.

Press Ctrl+C once to stop after the current probe and still save results. Press it twice to force exit.

Intended for authorized security assessment and learning purposes only.

options:

  -h, --help              Show this help message and exit
  
  --bucketnames NAME      Bucket name or file of bucket names
  
  --find-bucket           Only check whether buckets exist (probes the bucket root, no wordlist)
  
  --wordlist WORDLIST     File of filenames (required unless --find-bucket)
  
  --extensions EXT [...]  Extensions to append (default: txt)
  
  --region REGION         AWS region used to build the regional S3 endpoint (default: us-east-1)
  
  --s3-endpoint ENDPOINT  Optional custom S3 endpoint override
  
  --serial-port PORT      Modem serial port (default: /dev/ttyUSB0)
  
  --baudrate BAUDRATE     Baud rate (default: 115200)
  
  --delay DELAY           Seconds between probes (default: 1.0)
  
  --read-body             Retrieve response body; default file probes request only one byte
  
  --download-dir DIR      Save HTTP 200 response body as local file in this directory
  
  --out OUT               Output prefix; a YYYYMMDD_HHMMSS timestamp is appended (default: cells3enum_results)
  
  --assume-on             Skip RDY wait (Use when cell module already on.)
  
  --verbose               Verbose modem logging
  
  --interactive           Launch the guided setup prompts
