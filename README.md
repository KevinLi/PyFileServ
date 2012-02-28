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
* If the puush client is used on Windows, add the following to %appdata%\puush\puush.ini:
    * ProxyServer = IP address or hostname
    * ProxyPort = PORT
* Start server using screen, nohup, or &.
* Visit http://HOST:PORT/ for web-accessible pages

###Usage###
* Puush Desktop Client
    * Can be used normally
    * Versions tested:
        * r82 (Windows 7 x64 Ultimate SP1)
        * r83 (Windows 7 x64 Ultimate SP1)
* Curl
    * curl -F "key=data" -F "another_key=@/home/aoeu.png" host:port/url

###Notes###
* JSON data of a file can be accessed at http://HOST:PORT/api?file=filename

###Known bugs###
* Memory usage increases insanely if spammed
* Client crashes on cancellation of upload
