// Standard libraries
#include <iostream>
#include <string>
#include <cstdlib>
#ifdef _WIN32
#include <Windows.h>
#endif
using namespace std;

// Include cryptopp libraries
#include <cryptopp/aes.h>
using CryptoPP::AES;

#include <cryptopp/osrng.h>
using CryptoPP::AutoSeededRandomPool;

#include <cryptopp/cryptlib.h>
using CryptoPP::Exception;

#include <cryptopp/hex.h>
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;

#include <cryptopp/filters.h>
using CryptoPP::ArraySink;
using CryptoPP::ArraySource;
using CryptoPP::StreamTransformationFilter;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;
using CryptoPP::Redirector;

#include <cryptopp/files.h>
using CryptoPP::FileSource;
using CryptoPP::FileSink;

#include "cryptopp/modes.h"
#include "cryptopp/xts.h"
#include "cryptopp/ccm.h"
#include "cryptopp/gcm.h"
using CryptoPP::CBC_Mode;
using CryptoPP::ECB_Mode;
using CryptoPP::CFB_Mode;
using CryptoPP::OFB_Mode;
using CryptoPP::CTR_Mode;
using CryptoPP::CCM;
using CryptoPP::GCM;

const int TAG_SIZE = 8; // used in mode CCM

// Support Vietnamese
void supportVietnamese();

string ecb_encrypt(string, CryptoPP::byte*);
string ecb_decrypt(string, CryptoPP::byte*);
string cbc_encrypt(string, CryptoPP::byte*, CryptoPP::byte*);
string cbc_decrypt(string, CryptoPP::byte*, CryptoPP::byte*);
string cfb_encrypt(string, CryptoPP::byte*, CryptoPP::byte*);
string cfb_decrypt(string, CryptoPP::byte*, CryptoPP::byte*);
string ofb_encrypt(string, CryptoPP::byte*, CryptoPP::byte*);
string ofb_decrypt(string, CryptoPP::byte*, CryptoPP::byte*);
string ctr_encrypt(string, CryptoPP::byte*, CryptoPP::byte*);
string ctr_decrypt(string, CryptoPP::byte*, CryptoPP::byte*);
string xts_encrypt(string, CryptoPP::byte*, CryptoPP::byte*);
string xts_decrypt(string, CryptoPP::byte*, CryptoPP::byte*);
string gcm_encrypt(string, CryptoPP::byte*, CryptoPP::byte*);
string gcm_decrypt(string, CryptoPP::byte*, CryptoPP::byte*);
string ccm_encrypt(string, CryptoPP::byte*, CryptoPP::byte*);
string ccm_decrypt(string, CryptoPP::byte*, CryptoPP::byte*);

void supportVietnamese()
{
    #ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    #elif _linux_
    setlocale(LC_ALL, "")
    #endif
}

string ecb_encrypt(string plain, CryptoPP::byte *key)
{
    string encoded, cipher;
    try
    {
        ECB_Mode<AES>::Encryption e;
        e.SetKey(key, AES::DEFAULT_KEYLENGTH);
        StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    // Print cipher in hex
    StringSource(cipher, true, new HexEncoder(new StringSink(encoded)));
    return encoded;
}

string ecb_decrypt(string cipher, CryptoPP::byte *key)
{
    string recovered;
    try
    {
        ECB_Mode<AES>::Decryption d;
        d.SetKey(key, AES::DEFAULT_KEYLENGTH);
        StringSource(cipher, true, new HexDecoder(new StreamTransformationFilter(d, new StringSink(recovered))));
    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    return recovered;
}

string cbc_encrypt(string plain, CryptoPP::byte *key, CryptoPP::byte *iv)
{
    string encoded, cipher;
    try
    {
        CBC_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
        StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));

#if 0
		StreamTransformationFilter filter(e);
		filter.Put((const byte*)plain.data(), plain.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		cipher.resize(ret);
		filter.Get((byte*)cipher.data(), cipher.size());
#endif

    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    StringSource(cipher, true, new HexEncoder(new StringSink(encoded)));
    return encoded;
}

string cbc_decrypt(string cipher, CryptoPP::byte* key, CryptoPP::byte *iv)
{
    string recovered;
    try
    {
        
        CBC_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
        StringSource (cipher, true, new HexDecoder(new StreamTransformationFilter(d, new StringSink(recovered))));

#if 0
		StreamTransformationFilter filter(d);
		filter.Put((const byte*)cipher.data(), cipher.size());
		filter.MessageEnd();

		const size_t ret = filter.MaxRetrievable();
		recovered.resize(ret);
		filter.Get((byte*)recovered.data(), recovered.size());
#endif

    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    return recovered;
}

string cfb_encrypt(string plain, CryptoPP::byte *key, CryptoPP::byte *iv)
{
    string encoded, cipher;
    try
    {
        CFB_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
        StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
    }
    catch (const Exception& e) {
        cerr << e.what() << endl;
        exit(1);
    }

    StringSource(cipher, true, new HexEncoder(new StringSink(encoded)));
    return encoded;
}

string cfb_decrypt(string cipher, CryptoPP::byte *key, CryptoPP::byte *iv)
{
    string recovered;
    try
    {
        CFB_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
        StringSource (cipher, true, new HexDecoder(new StreamTransformationFilter(d, new StringSink(recovered))));
    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    return recovered;
}

string ofb_encrypt(string plain, CryptoPP::byte *key, CryptoPP::byte *iv)
{
    string encoded, cipher;
    try
    {
        OFB_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
        StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    StringSource(cipher, true, new HexEncoder(new StringSink(encoded)));
    return encoded;
}

string ofb_decrypt(string cipher, CryptoPP::byte *key, CryptoPP::byte *iv)
{
    string recovered;
    try
    {
        OFB_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
        StringSource(cipher, true, new HexDecoder(new StreamTransformationFilter(d, new StringSink(recovered))));
    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    return recovered;
}

string ctr_encrypt(string plain, CryptoPP::byte *key, CryptoPP::byte *iv)
{
    string encoded, cipher;
    try
    {
        CTR_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
        StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher)));
    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    StringSource(cipher, true, new HexEncoder(new StringSink(encoded)));

    return encoded;
}

string ctr_decrypt(string cipher, CryptoPP::byte *key, CryptoPP::byte *iv)
{
    string recovered;
    try
    {    
        CTR_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv);
        StringSource (cipher, true, new HexDecoder(new StreamTransformationFilter(d, new StringSink(recovered))));
    }
    catch (const Exception& e) {
        cerr << e.what() << endl;
        exit(1);
    }

    return recovered;
}

string xts_encrypt(string plain, CryptoPP::byte *key, CryptoPP::byte *iv)
{
    string encoded, cipher;
    try
    {
        CryptoPP::XTS_Mode<AES>::Encryption e;
        e.SetKeyWithIV(key, 32, iv);

#if 0
        std::cout << "key length: " << enc.DefaultKeyLength() << std::endl;
        std::cout << "key length (min): " << enc.MinKeyLength() << std::endl;
        std::cout << "key length (max): " << enc.MaxKeyLength() << std::endl;
        std::cout << "block size: " << enc.BlockSize() << std::endl;
#endif
        
        StringSource(plain, true, new StreamTransformationFilter(e, new StringSink(cipher), StreamTransformationFilter::NO_PADDING));
    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    StringSource(cipher, true, new HexEncoder(new StringSink(encoded)));
    return encoded;
}

string xts_decrypt(string cipher, CryptoPP::byte *key, CryptoPP::byte *iv)
{
    string recovered;
    try
    {    
        CryptoPP::XTS_Mode<AES>::Decryption d;
        d.SetKeyWithIV(key, 32, iv);
        StringSource (cipher,
                    true,
                    new HexDecoder(new StreamTransformationFilter(d, new StringSink(recovered), StreamTransformationFilter::NO_PADDING)));
    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    return recovered;
}

string gcm_encrypt(string plain, CryptoPP::byte *key, CryptoPP::byte *iv)
{
    string encoded, cipher;
    try
    {
        GCM<AES>::Encryption e;
        e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv, AES::BLOCKSIZE);
        StringSource(plain, true, new AuthenticatedEncryptionFilter(e, new StringSink(cipher) ));
    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    StringSource(cipher, true, new HexEncoder(new StringSink(encoded)));

    return encoded;
}

string gcm_decrypt(string cipher, CryptoPP::byte *key, CryptoPP::byte *iv)
{
    string recovered;
    try
    {
        GCM<AES>::Decryption d;
        d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv, AES::BLOCKSIZE);
        StringSource (cipher, true, new HexDecoder(new AuthenticatedDecryptionFilter(d, new StringSink(recovered))));
    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    return recovered;
}

string ccm_encrypt(string plain, CryptoPP::byte *key, CryptoPP::byte *iv)
{
    string encoded, cipher;
    try
    {
        CCM<AES, TAG_SIZE>::Encryption e;
        e.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv, 12);
        e.SpecifyDataLengths(0, plain.size(), 0);
        StringSource(plain, true, new AuthenticatedEncryptionFilter(e, new StringSink(cipher)));
    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    StringSource(cipher, true, new HexEncoder(new StringSink(encoded)));
    return encoded;
}

string ccm_decrypt(string cipher, CryptoPP::byte *key, CryptoPP::byte *iv)
{
    string recovered, cipher_hex_decoded;
    try
    {
        CCM<AES, TAG_SIZE>::Decryption d;
        d.SetKeyWithIV(key, AES::DEFAULT_KEYLENGTH, iv, 12);

        // Decode cipher
        StringSource(cipher, true, new HexDecoder(new StringSink(cipher_hex_decoded)));

        d.SpecifyDataLengths(0, cipher_hex_decoded.size() - TAG_SIZE, 0);
        AuthenticatedDecryptionFilter adf(d, new StringSink(recovered));
        StringSource(cipher_hex_decoded, true, new Redirector(adf));

        if (adf.GetLastResult())
        {
            return recovered;
        }
    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }

    return NULL;
}