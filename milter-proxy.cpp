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
#define PORT "7777"

std::string server;
std::string api_key;
std::mutex gmutex;

std::string pid_file;

struct mlfiPriv
{
	char	*mlfi_fname;
	FILE	*mlfi_fp;
};

#define MLFIPRIV	((struct mlfiPriv *) smfi_getpriv(ctx))

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

		if(func == "mlfi_envrcpt")
		{ // FIRST ENTRYPOINT TO COMMUNICATE
			std::string data = Serialize();
			ret = Communicate(data);
		}
		else if(func == "mlfi_eoh")
		{ // SECOND ENTRYPOINT TO COMMUNICATE
			std::string data = Serialize();
			ret = Communicate(data);

//			smfi_setmlreply(ctx, "550", "5.7.0", "Spammer access rejected", "Please see our policy at:", "http://www.example.com/spampolicy.html", NULL);
//			return SMFIS_REJECT;
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
		auto len = aes_encrypt((unsigned char*)input.c_str(), input.size(), (unsigned char*)key_.c_str(), (unsigned char*)iv_.c_str(), ciphertext, true);
		if(len > 0)
		{
			output = "";
			output.append((char*)ciphertext, len);
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

		unsigned char *plaintext = new unsigned char[input.size() + 64];
		auto len = aes_decrypt((unsigned char*)input.c_str(), input.size(), (unsigned char*)key_.c_str(), (unsigned char*)iv_.c_str(), plaintext, true);

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

		ret = std::string("<ASPF>") + ret + std::string("</ASPF>");

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
	int Communicate(std::string &data)
	{
		std::string header;
		std::map<int,std::string> ex;
		if(ASPF_KEY.size() != 64)
		{
			//smfi_setreply(ctx,(char*)"451",NULL,(char*)"ASPF: Invalid API_KEY");
			return SMFIS_CONTINUE;
		}

		std::string UUID = ASPF_KEY.substr(0,8);
		std::string ts = md5(tostr(data.size()) + tostr(time(NULL)),false).substr(0,8);
		std::string iv = md5(ts,true);
		std::string key = md5(ASPF_KEY,true);

		std::string encrypted;
		if(!Encrypt(key, iv, data, encrypted))
		{
			smfi_setreply(ctx,(char*)"451",NULL,(char*)"ASPF: Encryption Failed");
			return SMFIS_TEMPFAIL;
		}
		header = UUID + std::string("#") + ts + std::string("#") + tostr(data.size()) + "\n";

		/** NETWORK_STACK **/
		int error;
		struct addrinfo hints, *res, *res0;

		memset(&hints, 0, sizeof(hints));
		hints.ai_family = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;
		error = getaddrinfo(ASPF_SERVER.c_str(), PORT, &hints, &res0);

		if (error)
		{
			//smfi_setreply(ctx,(char*)"451",NULL,(char*)std::string(std::string("ASPF: Socket Error #") + tostr(__LINE__)).c_str());
			return SMFIS_CONTINUE;
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
						if(socket_write(sock,encrypted) > 0)
						{




							success = true;
						}
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
			//smfi_setreply(ctx,(char*)"451",NULL,(char*)std::string(std::string("ASPF: Socket Error #") + tostr(__LINE__)).c_str());
			return SMFIS_CONTINUE;
		}

		return SMFIS_CONTINUE;
	}
	/** COMMUNICATE **/


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
	ASPF->Set("FROM",envfrom[0]);
	ASPF->Set("QID",symval(ctx,"i"));
	ASPF->Set("AUTH",symval(ctx,"{auth_authen}"));
	ASPF->Set("ATYPE",symval(ctx,"{auth_type}"));
	ASPF->From(envfrom[0]);

/* Useless at the moment
	ASPF->Set("TLSV",symval(ctx,"tls_version"));
	ASPF->Set("C_SUBJECT",symval(ctx,"cert_subject"));
	ASPF->Set("C_ISSUER",symval(ctx,"cert_issuer"));
*/

	return ASPF->Handle("mlfi_envfrom");	
}

sfsistat mlfi_envrcpt(SMFICTX* ctx, char** envrcpt)
{
	ASPFConnector *ASPF = (ASPFConnector*)smfi_getpriv(ctx);
	ASPF->To(envrcpt[0]);

	return ASPF->Handle("mlfi_envrcpt");	
}

sfsistat mlfi_cleanup(SMFICTX *ctx, bool ok)
{
	ASPFConnector *ASPF = (ASPFConnector*)smfi_getpriv(ctx);
	delete ASPF;

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

	return ASPF->Handle("mlfi_eoh");	
}

sfsistat mlfi_body(SMFICTX *ctx, u_char *bodyp, size_t bodylen)
{
	return SMFIS_CONTINUE;
}

sfsistat mlfi_eom(SMFICTX *ctx)
{
	return mlfi_cleanup(ctx, true);
}

sfsistat
mlfi_close(SMFICTX *ctx)
{
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
	*pf0 = SMFIF_ADDHDRS;

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
	SMFIF_ADDHDRS,	/* flags */
	mlfi_connect,		/* connection info filter */
	mlfi_helo,		/* SMTP HELO command filter */
	mlfi_envfrom,	/* envelope sender filter */
	mlfi_envrcpt,		/* envelope recipient filter */
	mlfi_header,	/* header filter */
	mlfi_eoh,	/* end of header */
	mlfi_body,	/* body block filter */
	mlfi_eom,	/* end of message */
	mlfi_abort,	/* message aborted */
	mlfi_close,	/* connection cleanup */
	mlfi_unknown,	/* unknown/unimplemented SMTP commands */
	mlfi_data,	/* DATA command filter */
	mlfi_negotiate	/* option negotiation at connection startup */
};
/** MILTER_UTILS **/

int
main(int argc, char *argv[])
{
    if(argc < 3)
    {
        std::cerr << "Usage: " << argv[0] << " [BIND_PARAMETERS] [MASTER_SERVER] [API_KEY] {PID_FILE}" << std::endl;        
        std::cerr << "Example (StandAlone): " << argv[0] << " inet:9999 aspf.npulse.net 93D8874C8C86F0FC893DBE15C765FFA0FCD342F798DBF669E08F8CBE095D230C" << std::endl;        
        std::cerr << "Example (Daemon): " << argv[0] << " inet:9999 aspf.npulse.net 93D8874C8C86F0FC893DBE15C765FFA0FCD342F798DBF669E08F8CBE095D230C /var/run/aspf.pid" << std::endl;        
        exit(EX_UNAVAILABLE);
    }

	std::cerr << "ASPF | Initialising Proxy Module ..." << std::endl;

    server = argv[2];
    api_key = argv[3];

	if(server.size() != 64)
	{
		std::cerr << "ASPF | Error: API Key size invalid" << std::endl;
	}
	
	if(argc >= 4)
	{
		pid_file = argv[4];
	}

	(void) smfi_setconn(argv[1]);
	if (smfi_register(smfilter) == MI_FAILURE)
	{
        std::cerr << "Initialisation Failed" << std::endl;        
		exit(EX_UNAVAILABLE);
	}

	struct passwd *PWD = getpwnam("nobody");
	if(!PWD)
	{
		std::cerr << "ASPF | Error: Unable to setuid to nobody" << std::endl;
        exit(EX_UNAVAILABLE);
	}

	if(setuid(PWD->pw_uid) != 0)
	{
		std::cerr << "ASPF | Error: Unable to setuid to nobody" << std::endl;
        exit(EX_UNAVAILABLE);
	}

	if(pid_file.size())
	{
    	pid_t pid, sid = fork();

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
			std::cerr << "ASPF | Started as Daemon" << std::endl;
			writeFile(pid_file,tostr(pid));
			exit(0);
		}
		else
		{
			std::cerr << "ASPF | Error: Fork Failed" << std::endl;
			exit(EX_UNAVAILABLE);
		}		
	}


	return smfi_main();
}
