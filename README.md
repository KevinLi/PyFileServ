##PyPuush##
***
A Puush Server. In Python.
***
This script allows the saving and management of files captured with puush or other programs to a server.

###Requirements###
* Python
    * Versions tested:
        * Python 2.6.6 (CentOS 6 x86)
        * Python 2.7.2 (Windows 7 x64 Ultimate SP1)

###Configuration###
* Run script to generate config file.
* An account is needed to upload. Register at http://HOST:PORT/register
* Remember to disable registration from the admin page afterwards.
* Start server using screen, nohup, or &.
* Visit http://HOST:PORT/ for web-accessible pages

###Usage###
* Puush Desktop Client
	* If the client is used on Windows, add or change the following in %appdata%\puush\puush.ini:
		* ProxyServer = IP address or hostname of server
		* ProxyPort = PORT
    * Versions tested:
        * r82 (Windows 7 x64 Ultimate SP1)
        * r83 (Windows 7 x64 Ultimate SP1)
* Curl
    * curl -F "k=key" -F "f=@/home/santorum/frothy.png" host:port/url
	* Authentication
			* Returns: "Quota(1 or 0),UserAPIKey,,UsageInBytes"
		* k: key
		* z: "poop" (r83 client)
		* e: email
		* p: password (Authentication through client login window)
	* Upload (Client) (/up)
			* Returns: "0,URL,FileNumber,FileUsageInBytes"
		* c: unknown
		* z: "poop"
		* k: key
		* f: file
	* Upload (Web) (/upload)
			* Returns: HTML page with link to uploaded image
		* e: email
		* p: password
		* f: file
	* Deletion (/del)
			* Returns: JSON formatted history
		* i: item number
		* k: key
	* History (/hist?key=userkey)
			* Returns: JSON formatted history
		* k: key
	* Registration (/register)
		* e: email
		* p: password
		* q: password (again)
	* Administration (/admin)
		* p: password (mandatory)
		* d: file deletion (list of item numbers to be deleted)
		* q: quota toggle (1/0)
		* r: registration toggle (1/0)
		* a: api toggle (1/0)
		* l: reload configuration
		* n: new password

###Notes###
* JSON formatted file data can be accessed at http://HOST:PORT/api?file=filename
* JSON formatted upload history can be accessed at http://HOST:PORT/hist?key=APIKEY

###Known bugs###
* Memory usage increases insanely if spammed. Caused by broken pipes?
* Client crashes on cancellation of upload
