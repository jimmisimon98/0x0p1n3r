import socket
import  sys

url=sys.argv[1]
try:
	host = socket.gethostbyname(url)
	print(url," : ",host)
except:
	print("Error in Finding IP of : ",url)
