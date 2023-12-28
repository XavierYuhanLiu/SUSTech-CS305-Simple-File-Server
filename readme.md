# CS305 Computer Network Project  

Our server supports three kinds of HTTP methods, *GET*, *HEAD* and *POST*  
Port is set to 8080 by default.  
Using persistent connection if 'Connection' is not set to 'close'.

## How do I set up a server?
To set up the server, execute script **'run.sh'**

## How to do testing?
Under directory *test_pkg*, we have an official testfile *official_test*, it may upload some file in directory *test_pkg/tmp*.  
(This file is downloaded from blackboard directly, no additional changes)

## GET
localhost:8080/*relative_path_to_data*?*params*  
For example, I have a file called *tommy.jpg* under the directory *./data/11911922*,
then relative_path is set to *11911922/tommy.jpg* 

In params, chunk=1 means the client needs the file to be transferred chunked, otherwise we'll set a Content-Length.  
SUSTech-HTTP=0 means \**Blank*\*  
SUSTech-HTTP=1 means \**Blank*\*

## POST
Here are two examples of upload and delete. Makesure argument path correspond to the username in key *Authorization*.  
UPLOAD url:
http://localhost:8080/upload?path=/11911922/  
When uploading, the content of the file will be in form-data in request body.

DELETE url:
http://localhost:8080/delete?path=/11911922/abc.txt  
As long as the username matches and the file exists, the deletion will success.



## TODO
Breakpoint transmission
