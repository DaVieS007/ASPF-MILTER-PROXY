/**
 * Name: ASPF-MILTER Proxy Module
 * Description: 
 * This module is act as milter and all requests proxied securely into ASPF UPStream server. 
 * It uses AES128-CBC Encryption Mechanism.
 * Data proxied: Mail headers, Sender, Recipient, IP Address, Mail Server FQDN
 * Mail body will not send
 * 
 * Requirements: libmilter, libopenssl, libpthread
 * 
 * Compiling on BSD: clang++ -o milter milter-proxy.cpp -lmilter -lpthread -lcrypto
 * Compiling on Linux: g++ -o milter milter-proxy.cpp -lmilter -lpthread -lcrypto
 * 
 * Author: DaVieS / davies@npulse.net | Viktor Hlavaji
 * License: BSD
 * 
 **/

#include <iostream>
#include <sstream>
#include <fstream>
#include <map>
#include <syslog.h>

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>
#include <unistd.h>

#include <sys/socket.h> 
#include <stdlib.h> 
#include <netinet/in.h> 
#include <netdb.h>

#include "libmilter/mfapi.h"
#include "libmilter/mfdef.h"

#include <openssl/ssl.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/md5.h>

#include <sys/types.h>
#include <pwd.h>
#include <unistd.h>

#define _ASPF_ "ASPF"
#define NEXUS_BUFFER 4194304

std::string server;
std::string api_key;
std::string port;
std::mutex logmutex;
bool standalone;

std::mutex gmutex;

std::string pid_file;

struct mlfiPriv
{
	char	*mlfi_fname;
	FILE	*mlfi_fp;
};

#define MLFIPRIV	((struct mlfiPriv *) smfi_getpriv(ctx))
#define COMERROR SMFIS_CONTINUE

static unsigned long mta_caps = 0;

/** GLOBAL UTILS **/
/** TOSTR **/
template <class T>
std::string tostr (T val)
{
	std::stringstream out;
	out << val;
	return out.str();
}
/** TOSTR **/

void log(int type, std::string msg)
{
	std::string tp;

	if(type == LOG_EMERG)
	{
		tp = "[EMERG]";
	}
	else if(type == LOG_CRIT)
	{
		tp = "[CRITICAL]";
	}
	else if(type == LOG_ERR)
	{
		tp = "[ERROR]";
	}
	else if(type == LOG_WARNING)
	{
		tp = "[WARNING]";
	}
	else if(type == LOG_NOTICE)
	{
		tp = "[NOTICE]";
	}
	else if(type == LOG_INFO)
	{
		tp = "[INFO]";
	}
	else if(type == LOG_DEBUG)
	{
		tp = "[DEBUG]";
	}
	else if(type == LOG_ALERT)
	{
		tp = "[ALERT]";
	}


	logmutex.lock();
	syslog(type, "%s", msg.c_str());
	if(standalone)
	{
		std::cerr << tp << " | ASPF | " << msg << std::endl;
	}
	logmutex.unlock();
}

/** writeFile **/
bool writeFile(std::string file, std::string data)
{
    std::ofstream fs;
    fs.open(file.c_str(),std::ios::binary);
    if(fs.is_open())
    {
        fs.write(data.c_str(),data.size());
        fs.close();
        return true;
    }

    return false;
}
/** writeFile **/

/** EXPLODE **/
std::map<int,std::string> explode (std::string exploder,std::string original, unsigned int occ)
{
	std::map<int,std::string> result;
	std::string tmp;
	tmp = original;
	int num;
	size_t loc;

	if(!exploder.size() || !original.size())
	{
		return result;
	}

	num=0;
	while (true)
	{
		loc = tmp.find(exploder);
		if(loc == std::string::npos)
		{
			break;
		}

		if(occ > 0 && (num + 1) >= occ)
		{
			break;
		}

		if(loc != 0)
		{
			result[num] = tmp.substr(0,loc);
		}
		else
		{
			result[num] = "";
		}
		
		num++;
		tmp = tmp.substr(loc + exploder.size());
	}

	//num++;
	result[num] += tmp;

	return result;
}
/** EXPLODE **/

/** GLOBAL UTILS **/

/** ASPFCONNECTOR **/
class ASPFConnector
{
	public: 

	/** CONSTRUCTOR **/
	ASPFConnector(SMFICTX *_ctx)
	{
		ctx = _ctx;

		gmutex.lock();
		ASPF_SERVER = server;
		ASPF_KEY = api_key;
		gmutex.unlock();
	}
	/** CONSTRUCTOR **/

	/** DESTRUCTOR **/
	~ASPFConnector()
	{

	}
	/** DESTRUCTOR **/

	/** HANDLE **/
	int Handle(std::string func)
	{
		int ret = SMFIS_CONTINUE;
		Set("FUNC",func);

		if(func == "mlfi_eom")
		{
			Set("SMTP","postfix.milter");
			std::string data = Serialize();
			ret = Communicate(data);

			if(rdata["ACTION"] == "REJECT")
			{
				smfi_setreply(ctx, (char*)rdata["CODE"].c_str(), (char*)rdata["ECODE"].c_str(), (char*)rdata["MESSAGE"].c_str());
				return SMFIS_REJECT;
			}
			else
			{

				if(rdata["ADDHDR"].size() > 0)
				{
					if(rdata["ADDHDR"].find("\n") != std::string::npos)
					{
						std::map<int,std::string> ex = explode(";\n",rdata["ADDHDR"],0);
						for (std::map<int,std::string>::iterator it=ex.begin(); it!=ex.end(); ++it)
						{
							if(it->second.find(": ") != std::string::npos)
							{
								std::map<int,std::string> ex2 = explode(": ",it->second,2);
								if(ex2[0].size() > 0)
								{
									for(int i = 0;i<100;i++)
									{
										smfi_chgheader(ctx, (char*)ex2[0].c_str(), i, NULL); // DELETE EXISTING
									}
								}
							}
						}

						for (std::map<int,std::string>::iterator it=ex.begin(); it!=ex.end(); ++it)
						{
							if(it->second.find(": ") != std::string::npos)
							{
								std::map<int,std::string> ex2 = explode(": ",it->second,2);
								if(ex2[0].size() > 0)
								{
									smfi_addheader(ctx, (char*)ex2[0].c_str(), (char*)ex2[1].c_str());			
//									smfi_insheader(ctx, 0, (char*)ex2[0].c_str(), (char*)ex2[1].c_str());			
								}
							}
						}

					}
				}


				return SMFIS_CONTINUE;
			}
/*
			smfi_setmlreply(ctx, "550", "5.7.0", "Spammer access rejected", "Please see our policy at:", "http://www.example.com/spampolicy.html", NULL);
*/
		}

		return ret;
	}
	/** HANDLE **/

    /** BIN_VALUE **/
    int bin_value(char ch)
    {
		if('0'<=ch && ch<='9')
		{
			return ch - '0';
		}
		else if('a'<=ch && ch<='z')
		{
			return ch - 'a' + 0x0A;
		}
		else if('A'<=ch && ch<='Z')
		{
			return ch - 'A' + 0x0A;
		}
		else
		{
			return -1;
		}
    }
    /** BIN_VALUE **/

    /** HEX2BIN **/
    void hex2bin(char *bin,char *hex,int len)
    {
        int		i,l = 0;
        char		c1,c2;
        for(i = 0; i < len / 2; i++)
        {
            c1 = (bin_value(hex[l++])<<4) & 0xF0;
            c2 = (bin_value(hex[l++])   ) & 0x0F;

            bin[i] = c1 | c2;
        }
        bin[i] = 0;
    }
    /** HEX2BIN **/

    /** BIN2HEX **/
    void bin2hex(char *hex,char *bin,int len)
    {
        unsigned char		i;
        unsigned char		c;
        unsigned int		l = 0;
        static char strhex[]="0123456789ABCDEF";

        for(i = 0; i < len; i++)
        {
            c = bin[i];
            hex[l++] = strhex[(c >> 4)&0x0F];
            hex[l++] = strhex[(c & 0x0f)&0x0F];
        }
        hex[l] = 0;
    }
    /** BIN2HEX **/

	/** BIN2HEX **/
    std::string bin2hex(std::string in)
    {
        std::string ret = "";
        char buffer[2],buffer2[5];
        unsigned int i;

        buffer[0] = 0x00;

        for(i=0;i<in.size();i++)
        {
            buffer[0] = in.at(i);
            buffer[1] = 0x00;

            buffer2[0] = 0x00;
            bin2hex(buffer2,buffer,1);
            ret.append(buffer2,2);
        }

        return ret;
    }
    /** BIN2HEX **/

    /** HEX2BIN **/
    std::string hex2bin(std::string in)
    {
        std::string ret = "";
        char buffer[5],buffer2[2];
        unsigned int i;

        for(i=0;i<in.size();i++)
        {
            if(i + 1 < in.size())
            {
                buffer[0] = in.at(i);
                buffer[1] = in.at(i + 1);
                buffer[2] = 0x00;
                i++;

                buffer2[0] = 0x00;
                hex2bin(buffer2,buffer,2);
                ret.append(buffer2,1);

            }
        }

        return ret;
    }
    /** HEX2BIN **/

	/** MD5 **/
	std::string md5(std::string data, bool raw)
	{
		std::string ret = "";

		MD5_CTX ctx;
		unsigned char hash[MD5_DIGEST_LENGTH];

		MD5_Init(&ctx);
		MD5_Update(&ctx, (const unsigned char*)data.c_str(), data.size());   
		MD5_Final(hash,&ctx);  
		
		ret.append((char*)hash,MD5_DIGEST_LENGTH);

		if(raw)
		{
			return ret;
		}
		else
		{
			return bin2hex(ret);
		}
	}
	/** MD5 **/

	/** SHA256 **/
	std::string sha256(std::string data, bool raw)
	{
		std::string ret = "";

		SHA256_CTX ctx;
		unsigned char hash[SHA256_DIGEST_LENGTH];

		SHA256_Init(&ctx);
		SHA256_Update(&ctx, (const unsigned char*)data.c_str(), data.size());   
		SHA256_Final(hash,&ctx);  
		
		ret.append((char*)hash,SHA256_DIGEST_LENGTH);

		if(raw)
		{
			return ret;
		}
		else
		{
			return bin2hex(ret);
		}
	}
	/** SHA256 **/

	/** AES-LIB **/
	int aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key, unsigned char *iv, unsigned char *ciphertext, bool padding)
	{
		EVP_CIPHER_CTX *ctx;

		int len;
		int ciphertext_len;

		/* Create and initialise the context */
		if(!(ctx = EVP_CIPHER_CTX_new())) return -1;
		/* Initialise the encryption operation. IMPORTANT - ensure you use a key
		* and IV size appropriate for your cipher
		* In this example we are using 256 bit AES (i.e. a 256 bit key). The
		* IV size for *most* modes is the same as the block size. For AES this
		* is 128 bits */

		if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
		{
			EVP_CIPHER_CTX_free(ctx);
			return -1;
		} 

		if(!padding)
		{
		EVP_CIPHER_CTX_set_padding(ctx, 0);
		}

		/* Provide the message to be encrypted, and obtain the encrypted output.
		* EVP_EncryptUpdate can be called multiple times if necessary
		*/
		if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
		{
			EVP_CIPHER_CTX_free(ctx);
			return -1;
		}

		ciphertext_len = len;

		/* Finalise the encryption. Further ciphertext bytes may be written at
		* this stage.
		*/
		if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len))
		{
			EVP_CIPHER_CTX_free(ctx);
			return -1;
		}

		ciphertext_len += len;
		EVP_CIPHER_CTX_free(ctx);
		return ciphertext_len;
	}

	int aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key, unsigned char *iv, unsigned char *plaintext, bool padding)
	{
		EVP_CIPHER_CTX *ctx;

		int len;
		int ret;
		int plaintext_len;

		/* Create and initialise the context */
		if(!(ctx = EVP_CIPHER_CTX_new())) 
		{
			return -1;
		}

		/* Initialise the decryption operation. IMPORTANT - ensure you use a key
		* and IV size appropriate for your cipher
		* In this example we are using 256 bit AES (i.e. a 256 bit key). The
		* IV size for *most* modes is the same as the block size. For AES this
		* is 128 bits */
		if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
		{
			EVP_CIPHER_CTX_free(ctx);
			return -1;
		}

		if(!padding)
		{
		EVP_CIPHER_CTX_set_padding(ctx, 0);
		}


		/* Provide the message to be decrypted, and obtain the plaintext output.
		* EVP_DecryptUpdate can be called multiple times if necessary
		*/

		ret = EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
		if(1 != ret)
		{
			EVP_CIPHER_CTX_free(ctx);
			return -1;
		}

		plaintext_len = len;

		/* Finalise the decryption. Further plaintext bytes may be written at
		* this stage.
		*/
		ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
		if(1 != ret)
		{
			EVP_CIPHER_CTX_free(ctx);
			return -1;
		}

		plaintext_len += len;
		EVP_CIPHER_CTX_free(ctx);
		return plaintext_len;
	}
	/** AES-LIB **/

	bool Encrypt(std::string key_, std::string iv_, const std::string& input, std::string& output) 
	{
		if(key_.size() != 16 || iv_.size() != 16)
		{
			return false;
		}

		unsigned char *ciphertext = new unsigned char[input.size() + 64];
		int len = aes_encrypt((unsigned char*)input.c_str(), input.size(), (unsigned char*)key_.c_str(), (unsigned char*)iv_.c_str(), ciphertext, true);
		if(len > 0)
		{
			output = "";
			output.append((char*)ciphertext, len);
			output = bin2hex(output);
			delete[] ciphertext;
			return true;
		}
		else
		{
			output = "";
			delete[] ciphertext;
			return false;
		}
	}


	bool Decrypt(std::string key_, std::string iv_, const std::string& input, std::string& output) 
	{
		if(key_.size() != 16 || iv_.size() != 16)
		{
			return false;
		}

		std::string t_input = hex2bin(input);

		unsigned char *plaintext = new unsigned char[t_input.size() + 64];
		int len = aes_decrypt((unsigned char*)t_input.c_str(), t_input.size(), (unsigned char*)key_.c_str(), (unsigned char*)iv_.c_str(), plaintext, true);

		if(len > 0)
		{
			output = "";
			output.append((char*)plaintext, len);
			delete[] plaintext;
			return true;
		}
		else
		{
			output = "";
			delete[] plaintext;
			return false;
		}


		return true;
	}

	/** HEADER **/
	void Header(std::string key, std::string val)
	{
		if(header.size())
		{
			header += "\x03";
		}
		header += key;
		header += "\x04";
		header += val;

		Set("HDR",header);
	}
	/** HEADER **/

	/** FROM **/
	void From(std::string val)
	{
		if(val.size())
		{
			if(from.size())
			{
				from += ",";
			}

			if(val.at(0) == '<')
			{
				val = val.substr(1,val.size() - 2);
			}

			from += val;
			Set("FROM", from);
		}
	}
	/** FROM **/

	/** TO **/
	void To(std::string val)
	{
		if(val.size())
		{
			if(to.size())
			{
				to += ",";
			}

			if(val.at(0) == '<')
			{
				val = val.substr(1,val.size() - 2);
			}

			to += val;
			Set("TO", to);
		}
	}
	/** TO **/

	/** SET **/
	void Set(std::string key, std::string val)
	{
		data[key] = val;
	}
	/** SET **/

	/** GET **/
	std::string Get(std::string key)
	{
		std::string ret = "";
		if(data.find( key ) != data.end())
		{
			ret = data[key];
		}

		return ret;
	}
	/** GET **/

	/** SERIALIZE **/
	std::string Serialize()
	{
		std::string ret;
		std::string tmp;

		for (std::map<std::string,std::string>::iterator it=data.begin(); it!=data.end(); ++it)
		{
			if(ret.size() > 0)
			{
				ret += "\x01";
			}
			ret += it->first + "\x02" + it->second;
		}

		return ret;
	}
	/** SERIALIZE **/

	/** SOCKET_WRITE **/
    int socket_write(int sock, std::string &data)
    {
        if(sock > 0)
        {
            int ret;
            unsigned int size,size2,size3;
            int sent = 0;

            size = data.size();

            if(sock < 0)
            {
                return -1;
            }

            if(!size)
            {
                return -1;
            }

            size2 = size;
            while(size2 > 0)
            {
                if(size2 > NEXUS_BUFFER)
                {
                    size3 = NEXUS_BUFFER;
                }
                else
                {
                    size3 = size2;
                }

				ret = send(sock, data.substr(data.size() - size2,size3).c_str(), size3, 0);
				sent += ret;

                if(ret < 1)
                {
                    return ret;
                }

                size2 -= ret;
            }
            return sent;
        }

        return -1;
    }
	/** SOCKET_WRITE **/

	/** COMMUNICATE **/
	int Communicate(std::string data)
	{
		com_error = "";
		retval = "";
		rdata.clear();

		std::string header;
		std::map<int,std::string> ex;
		if(ASPF_KEY.size() != 64)
		{
			//smfi_setreply(ctx,(char*)"451",NULL,(char*)"ASPF: Invalid API_KEY");
			return COMERROR;
		}

		std::string UUID = ASPF_KEY.substr(0,8);
		std::string ts = md5(tostr(data.size()) + tostr(time(NULL)),false).substr(0,8);
		std::string iv = md5(ts,true);
		std::string key = md5(ASPF_KEY,true);

		std::string encrypted;
		if(!Encrypt(key, iv, data, encrypted))
		{
			com_error = "Internal Error: AES-Encrypt Failed, Memory Issues?!";
			return COMERROR;
		}
		header = UUID + std::string("#") + ts + std::string("#") + encrypted + "\n";

		/** NETWORK_STACK **/
		int error;
		struct addrinfo hints, *res, *res0;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		error = getaddrinfo(ASPF_SERVER.c_str(), port.c_str(), &hints, &res0);

		if (error)
		{
			com_error = "Internal Error: Host Lookup Failure!";
			//smfi_setreply(ctx,(char*)"451",NULL,(char*)std::string(std::string("ASPF: Socket Error #") + tostr(__LINE__)).c_str());
			return COMERROR;
		}

		res = res0;
		bool success = false;

        while(res)
    	{
			int sock = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
			if(sock > 0)
            {
				if(connect(sock, res->ai_addr, res->ai_addrlen) == 0)
				{				
					if(socket_write(sock,header) > 0)
					{
						/** READ_DATA **/
						int ret;
						std::string response;
						char buffer[4096];
						buffer[0] = 0x00;

						while(true)
						{
							ret = recv(sock, buffer, 4096, 0);
							if(ret <= 0)
							{
								break;
							}

							response.append(buffer,ret);									

							if(response.find("\n") != std::string::npos)
							{

								break;
							}
							buffer[0] = 0x00;
						}
						/** READ_DATA **/

						if(response.find("\n") == std::string::npos)
						{
							
						}
						else
						{
							if(response.at(0) == 'E' && response.size() > 2)
							{
								retval = response.substr(1,response.size() -2);
								rdata["error"] = retval;
							}
							else if(response.find("#") != std::string::npos)
							{
								std::map<int,std::string> ex = explode("#",response.substr(0,response.size() - 1),2);
								std::string rts = ex[0];
								std::string tdata = ex[1];

								if(rts.size() == 8 && tdata.size())
								{
									std::string t_iv = md5(rts,true);
									std::string dbuff;
									if(!Decrypt(key, t_iv, tdata, dbuff))
									{
										com_error = "Internal Error: AES-Decrypt Failed, Memory Issues?!";
									}
									else
									{
										retval = dbuff;

										if(retval.find("\x01") != std::string::npos)
										{
											std::map<int,std::string> ex2;
											ex = explode("\x01",retval,0);
											for (std::map<int,std::string>::iterator it=ex.begin(); it!=ex.end(); ++it)
											{
												if(it->second.find("\x02") != std::string::npos)
												{
													ex2 = explode("\x02",it->second,2);
													rdata[ex2[0]] = ex2[1];
												}
											}
										}
									}
								}
							}
						}

						success = true;
					}
				}
				close(sock);
			}		

			if(success)
			{
				break;
			}
			res = res->ai_next;	
		}

		freeaddrinfo(res0); // CLEANUP
		/** NETWORK_STACK **/


		if(!success)
		{
			com_error = "Internal Error: Unable to connect!";
			return COMERROR;
		}

		return COMERROR;
	}
	/** COMMUNICATE **/

	std::string retval;
	std::string com_error;
	std::map<std::string,std::string> rdata;

	private:
	SMFICTX *ctx;
	std::map<std::string,std::string> data;
	std::string from, to, header;
	std::string ASPF_SERVER, ASPF_KEY;
};
/** ASPFCONNECTOR **/

/** MILTER_UTILS **/
std::string symval(SMFICTX * ctx, std::string key)
{
	std::string ret = "";
	char *tmp;
	tmp = smfi_getsymval(ctx, const_cast<char *>(key.c_str()));
	if(tmp)
	{
		ret = tmp;
	}
	return ret;
}

sfsistat mlfi_connect(SMFICTX * ctx, char *hostname, _SOCK_ADDR * hostaddr)
{
	ASPFConnector *ASPF = new ASPFConnector(ctx);
    const char *tmp;
    int res;

	if (!hostaddr)
	{
		ASPF->Set("connection_from","");
	} 
    else
	{
        char buff[NI_MAXHOST];
 		getnameinfo(hostaddr, sizeof(*hostaddr), buff, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
		ASPF->Set("IP",buff);
	}

	ASPF->Set("FQDN",symval(ctx,"j"));
	ASPF->Set("SA",symval(ctx,"_"));

	/* store a pointer to our private data with setpriv */
	res = smfi_setpriv(ctx, ASPF);
	if (res != MI_SUCCESS)
	{
		return SMFIS_TEMPFAIL;
	}

	return ASPF->Handle("mlfi_connect");
}

sfsistat mlfi_helo(SMFICTX * ctx, char * helohost)
{
	ASPFConnector *ASPF = (ASPFConnector*)smfi_getpriv(ctx);
	ASPF->Set("HELO",helohost);

	return ASPF->Handle("mlfi_helo");
}


sfsistat mlfi_envfrom(SMFICTX *ctx, char **envfrom)
{
	ASPFConnector *ASPF = (ASPFConnector*)smfi_getpriv(ctx);
	if(ASPF)
	{
		if(envfrom[0] != NULL)
		{
			ASPF->From(envfrom[0]);
		}

		ASPF->Set("QID",symval(ctx,"i"));
		ASPF->Set("AUTH",symval(ctx,"{auth_authen}"));
		ASPF->Set("ATYPE",symval(ctx,"{auth_type}"));

		/* Useless at the moment
			ASPF->Set("TLSV",symval(ctx,"tls_version"));
			ASPF->Set("C_SUBJECT",symval(ctx,"cert_subject"));
			ASPF->Set("C_ISSUER",symval(ctx,"cert_issuer"));
		*/

		return ASPF->Handle("mlfi_envfrom");	
	}
	else
	{
		return SMFIS_TEMPFAIL;
	}
}

sfsistat mlfi_envrcpt(SMFICTX* ctx, char** envrcpt)
{
	ASPFConnector *ASPF = (ASPFConnector*)smfi_getpriv(ctx);
	if(ASPF)
	{

		if(envrcpt[0] != NULL)
		{
			ASPF->To(envrcpt[0]);
		}

		return ASPF->Handle("mlfi_envrcpt");	
	}
	else
	{
		return SMFIS_TEMPFAIL;
	}
}

sfsistat mlfi_cleanup(SMFICTX *ctx, bool ok)
{
	ASPFConnector *ASPF = (ASPFConnector*)smfi_getpriv(ctx);
	if(ASPF)
	{
		delete ASPF;
		smfi_setpriv(ctx, NULL);
	}

	return SMFIS_CONTINUE;
}

sfsistat mlfi_header(SMFICTX *ctx, char *headerf, char *headerv)
{
	ASPFConnector *ASPF = (ASPFConnector*)smfi_getpriv(ctx);
	ASPF->Header(headerf, headerv);

	return ASPF->Handle("mlfi_header");	
}

sfsistat mlfi_eoh(SMFICTX *ctx)
{
	ASPFConnector *ASPF = (ASPFConnector*)smfi_getpriv(ctx);
	if(ASPF)
	{
		ASPF->Set("ID",symval(ctx,"i"));
		ASPF->Set("DAEMON_ADDR",symval(ctx,"{daemon_addr}"));
		ASPF->Set("CLIENT_ADDR",symval(ctx,"{client_addr}"));
		ASPF->Set("IF_ADDR",symval(ctx,"{if_addr}"));
		return ASPF->Handle("mlfi_eoh");	
	}

	return SMFIS_TEMPFAIL;
}

sfsistat mlfi_body(SMFICTX *ctx, u_char *bodyp, size_t bodylen)
{
	return SMFIS_CONTINUE;
}

sfsistat mlfi_eom(SMFICTX *ctx)
{
	ASPFConnector *ASPF = (ASPFConnector*)smfi_getpriv(ctx);
	if(ASPF)
	{
		return ASPF->Handle("mlfi_eom");	
	}

	return SMFIS_TEMPFAIL;
}

sfsistat mlfi_close(SMFICTX *ctx)
{
	mlfi_cleanup(ctx, true);
	return SMFIS_ACCEPT;
}

sfsistat mlfi_abort(SMFICTX *ctx)
{
	return mlfi_cleanup(ctx, false);
}

sfsistat mlfi_unknown(SMFICTX *ctx, const char *cmd)
{
	return SMFIS_CONTINUE;
}

sfsistat mlfi_data(SMFICTX *ctx)
{
	return SMFIS_CONTINUE;
}

sfsistat mlfi_negotiate(SMFICTX *ctx, unsigned long f0, unsigned long f1, unsigned long f2, unsigned long f3, unsigned long *pf0, unsigned long *pf1, unsigned long *pf2, unsigned long *pf3)
{
	/* milter actions: add headers */
	*pf0 = SMFIF_ADDHDRS | SMFIF_CHGHDRS;

	/* milter protocol steps: all but connect, HELO, RCPT */
	//*pf1 = SMFIP_NOCONNECT|SMFIP_NOHELO|SMFIP_NORCPT;
	mta_caps = f1;
	if ((mta_caps & SMFIP_NR_HDR) != 0)
		*pf1 |= SMFIP_NR_HDR;
	*pf2 = 0;
	*pf3 = 0;
	return SMFIS_CONTINUE;
}

struct smfiDesc smfilter =
{
	(char*)_ASPF_,	/* filter name */
	SMFI_VERSION,	/* version code -- do not change */
	SMFIF_ADDHDRS | SMFIF_CHGHDRS,	/* flags */
	mlfi_connect,		/* connection info filter */
	mlfi_helo,		/* SMTP HELO command filter */
	mlfi_envfrom,	/* envelope sender filter */
	mlfi_envrcpt,		/* envelope recipient filter */
	mlfi_header,	/* header filter */
	mlfi_eoh,	/* end of header */
	NULL /*mlfi_body*/,	/* body block filter */
	mlfi_eom,	/* end of message */
	mlfi_abort,	/* message aborted */
	mlfi_close,	/* connection cleanup */
	mlfi_unknown,	/* unknown/unimplemented SMTP commands */
	mlfi_data,	/* DATA command filter */
	mlfi_negotiate	/* option negotiation at connection startup */
};
/** MILTER_UTILS **/

int main(int argc, char *argv[])
{
	standalone = true;
    if(argc < 3)
    {
        std::cerr << "Usage: " << argv[0] << " [BIND_PARAMETERS] [MASTER_SERVER:PORT/API_KEY] {PID_FILE}" << std::endl;        
        std::cerr << "Example (StandAlone): " << argv[0] << " inet:9999 aspf.npulse.net:7777/93D8874C8C86F0FC893DBE15C765FFA0FCD342F798DBF669E08F8CBE095D230C" << std::endl;        
        std::cerr << "Example (Daemon): " << argv[0] << " inet:9999 aspf.npulse.net:7777/93D8874C8C86F0FC893DBE15C765FFA0FCD342F798DBF669E08F8CBE095D230C /var/run/aspf.pid" << std::endl;        
        exit(EX_UNAVAILABLE);
    }

	openlog("ASPF/Proxy", LOG_NOWAIT | LOG_PID, LOG_MAIL);
	log(LOG_NOTICE, "Initialising Proxy Module ...");
	smfi_setbacklog(40960);

	std::map<int,std::string> ex = explode("/",argv[2],2);
    server = ex[0];
	api_key = ex[1];

	ex = explode(":",server,2);
	
	port = ex[1];
	server = ex[0];

	if(api_key.size() != 64)
	{
		log(LOG_ALERT, "API Key size invalid");
		exit(EX_UNAVAILABLE);
	}
	
	if(argc >= 4)
	{
		pid_file = argv[3];
	}

	(void) smfi_setconn(argv[1]);
	if (smfi_register(smfilter) == MI_FAILURE)
	{
		log(LOG_ALERT, "Initialisation Failed");
		exit(EX_UNAVAILABLE);
	}

	struct passwd *PWD = getpwnam("nobody");
	if(!PWD)
	{
		log(LOG_ALERT, "Unable to setuid to nobody");
        exit(EX_UNAVAILABLE);
	}

	if(setuid(PWD->pw_uid) != 0)
	{
		log(LOG_ALERT, "Error: Unable to setuid to nobody");
        exit(EX_UNAVAILABLE);
	}


	ASPFConnector ASPF(NULL);
	log(LOG_NOTICE, "Initiating Connection Test");
	ASPF.Set("FUNC","CONTEST");
	ASPF.Set("PING","ASPF");
	ASPF.Communicate(ASPF.Serialize());

	if(ASPF.com_error.size() > 0)
	{
		log(LOG_WARNING, std::string("Connection Test Failed: ") + ASPF.com_error);
	}
	else if(ASPF.rdata["error"].size() > 0)
	{
		log(LOG_WARNING, std::string("Connection Test Failed: ") + ASPF.rdata["error"]);
	}
	else if(ASPF.rdata["PONG"] == "ASPF")
	{
		log(LOG_NOTICE, std::string("Connection Test Success"));
	}
	else
	{
		log(LOG_NOTICE, std::string("Connection Test Failed due unknown error"));
	}

	if(pid_file.size())
	{
		standalone = false;
    	pid_t pid = fork(), sid;

		if (pid == 0)
		{
			sid = setsid();

			if(sid < 0)
			{
				exit(EX_UNAVAILABLE);
			}

			close(STDIN_FILENO);
			close(STDOUT_FILENO);
			close(STDERR_FILENO);			
		}
		else if (pid > 0)
		{
			log(LOG_NOTICE, "Started as Daemon");
			writeFile(pid_file,tostr(pid));
			exit(0);
		}
		else
		{
			log(LOG_NOTICE, "Fork Failed");
			exit(EX_UNAVAILABLE);
		}		
	}
	else
	{
		log(LOG_NOTICE, "Started as Stand-Alone");
	}

	smfi_main();
	log(LOG_NOTICE, "Service Stopped");
	return 0;
}
