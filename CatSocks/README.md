#**CatSocks**

CatSocks.py is a socks5 proxy written in Python and designed to leverage Quectel AT commands to allow proxying of communication through a serial connect to a Quectel cell module.

This has not been tested with all Quectel cell modules and is considered a proof of concept tool and should be used with caution

This proxy currently will only allow a single socket conection, so using to establish application access which may require multople socks to work properly will fail. Future version of the POC will be written to support sockets connections up to the Quectel module limit of 12 sockets.


