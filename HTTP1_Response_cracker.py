import hashlib
import itertools

"""
	This script creates a list of possible Digest Auth, RFC 2617 responses. And compares them too the "actual_response" (perhaps found in a pcap file).
	
	For the script to work, you need to have the following information.
	username EG "webadmin"
	realm	EG "Pentester-Academy"
	request_type	EG "GET"
	URI	EG "/path/to/webpage"
	Nonce	EG  "X95LDujmBAA=9c8ec8a0aeee0ddf7f24a5a75c57d0f90245d0f5"
	NonceCount EG "00000001"
	ClientNonce EG "89b024ea3adb54ec"
	QOP	EG "auth"
	actual_response	EG "0fd7c603fdf61e89bfc9c95fb73e343a"
"""

# The following information can be used as a test, but fill in your own info here \/
username = "webadmin"
realm = "Pentester-Academy"
request_type = "GET"
URI = "/"
Nonce ="X95LDujmBAA=9c8ec8a0aeee0ddf7f24a5a75c57d0f90245d0f5"
NonceCount = "00000001"
ClientNonce = "89b024ea3adb54ec"
QOP = "auth"
actual_response = "0fd7c603fdf61e89bfc9c95fb73e343a"

def generate_wordlist(words, l):
        """
        :rtype : list
        :param words The string from which words should be made:
        :param l length of the strings:
        :return:
        """
        list_pass = []
        for i in itertools.product(words, repeat=l):
                list_pass.append("".join(i))
        return list_pass


def make_RFC2069_response():
	print("make_RFC2069_response function not finished. ")
	pass
	print("\n\nFUNCTION : hash_it_RFC2069 NOT FINISHED!!\n\n")
	hash1_string1 = str(username)+":"+str(realm)+":"+str(i)
	hash1_string2 = hash1_string1.encode('utf-8')
        
	hash2_string1 = "GET:lab/webapp/digest2/1"
	hash2_string2 = hash2_string1.encode('utf-8')

	nonce_string1 = ":"+str(nonse)+":"
	nonce_string2 = nonce_string1.encode('utf-8')

	hash1 = hashlib.md5(hash1_string2).hexdigest()
	hash2 = hashlib.md5(hash2_string2).hexdigest()

	hash1 = str(hash1).encode('utf-8')
	hash2 = str(hash2).encode('utf-8')

	full_response = hashlib.md5(hash1+nonce_string2+hash2)
	full_response = full_response.hexdigest()

def encode_string_utf_8(string):
	string = str(string)
	string = string.encode('utf-8')
	return string

def make_RFC2617_response(username, realm, password_string, request_type, URI, Nonce, NonceCount, ClientNonce, QOP):
	# EVERYTHING HAS TO B ENCODED TO UTF-8
	hash1_string1 = str(username)+":"+str(realm)+":"+str(password_string)
	hash1_string2 = encode_string_utf_8(hash1_string1)
        
	hash2_string1 = str(request_type)+":"+str(URI)
	hash2_string2 = encode_string_utf_8(hash2_string1)

	nonce_string1 = ":"+str(Nonce)
	nonce_string2 = encode_string_utf_8(nonce_string1)

	hash1 = hashlib.md5(hash1_string2).hexdigest()
	hash2 = hashlib.md5(hash2_string2).hexdigest()

	hash1 = encode_string_utf_8(hash1)
	hash2 = encode_string_utf_8(hash2)
	

	NonceCount = ":"+str(NonceCount)
	NonceCount = encode_string_utf_8(NonceCount)
	ClientNonce = ":"+str(ClientNonce)
	ClientNonce = encode_string_utf_8(ClientNonce)
	QOP = ":"+str(QOP)+":"
	QOP = encode_string_utf_8(QOP)

#	(Hash1:Nonce:NonceCount:ClientNonce:QOP:Hash2)

	full_response = hashlib.md5(hash1+nonce_string2+NonceCount+ClientNonce+QOP+hash2)
	full_response = full_response.hexdigest()
#	print("Response is : "+str(full_response))
	return full_response

def Crack():
	possible_password_list = generate_wordlist("xyz123", 6)
	for i in possible_password_list:
		possible_response = make_RFC2617_response(username, realm, i, request_type, URI, Nonce, NonceCount, ClientNonce, QOP)
		if possible_response == actual_response:
			print("WARNING: This script will run against Example data if unchanged...\nUsername is : "+str(username)+"\nPassword is : "+str(i))
			break

Crack()
