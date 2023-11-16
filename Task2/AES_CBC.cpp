#include <bits/stdc++.h>
#include <io.h>
#include <fcntl.h>
#include <codecvt>
#include <math.h>
#include "AES.h"
#ifdef _WIN32
#include <windows.h>
#endif
using namespace std;

// Chuyển từ string sang wstring
wstring convertStringToWString(const string&);

// Chuyển từ wstring sang string
string convertWStringToString(const wstring&);

// Khởi tạo giá trị đầu vào
void get_input(string&, string&, string&, int&);

int main()
{
    supportVietnamese();

    // Nhập input, key, IV và option (1: encrypt, 2: decrypt) từ bàn phím
    string input, key_s, iv_s;
    int option;
    get_input(input, key_s, iv_s, option);

    char c_input[1024];
    strcpy(c_input, input.c_str());

    string str_convert;

    for (int i = 0; i < key_s.length(); i += 2)
    {
        string byte = key_s.substr(i, 2);
        char chr = (char) (int)strtol(byte.c_str(), NULL, 16);
        str_convert.push_back(chr);
    }
    memcpy(key, str_convert.data(), str_convert.length());
    str_convert.clear();


    for (int i = 0; i < iv_s.length(); i += 2)
    {
        string byte = iv_s.substr(i, 2);
        char chr = (char) (int)strtol(byte.c_str(), NULL, 16);
        str_convert.push_back(chr);
    }
    memcpy(iv, str_convert.data(), str_convert.length());
    str_convert.clear();

    // Mở rộng key
    key_expansion_256();

    int size = 0;
    switch(option)
    {
        case 1:
            wcout << L"Ciphertext là: ";
            
            while (size < strlen(c_input))
            {
                size = encrypt_fill_block(size, c_input, in);

                // XOR với block ciphertext ngay trước (nếu là lần lặp đầu thì XOR với IV)
                for (int i = 0; i < sizeof(in); i++)
                {
                    in[i] ^= iv[i];
                }

                // Tiến hành mã hóa, kết quả lưu trong mảng out
                encrypt();

                for (int i = 0; i < sizeof(iv); i++)
                {
                    iv[i] = out[i];
                }

                for (int i = 0 ; i < 16 ; i++) 
                {
                    int x = (int)out[i];
                    if(x < 16) wcout << 0 << hex << x;
                    else wcout << hex << x; 
                }
            }

            break;

        case 2:
            // Nếu sau khi encrypt ta thực hiện tiếp decrypt
            if (size > 0) size = 0;

            // Chuyển các phần tử trong ciphertext từ hex sang byte
            string str(c_input);
            for (int i = 0; i < str.length(); i += 2)
            {
                string byte = str.substr(i, 2);
                char chr = (char) (int)strtol(byte.c_str(), NULL, 16);
                str_convert.push_back(chr);
            }
            memcpy(byteArr, str_convert.data(), str_convert.length());
            str_convert.clear();

            string ans = "";
            while (size < str.length()/2)
            {
                size = decrypt_fill_block(size, in, str.length()/2);

                // Tiến hành giải mã, kết quả lưu trong mảng out
                decrypt();

                // Block ciphertext sau khi được giải mã sẽ XOR với block ciphertext ngay trước nó (nếu là lần lặp đầu thì XOR với IV)
                for (int i = 0; i < sizeof(out); i++)
                {
                    out[i] ^= iv[i];
                }

                for (int i = 0; i < sizeof(iv); i++)
                {
                    iv[i] = in[i];
                }

                for (int i = 0; i < 16; i++) ans += out[i];
            }
            wcout << L"Plaitext after decrypted: " << convertStringToWString(ans) << endl;

            break;
    }

    return 0;
}

wstring convertStringToWString(const string &str)
{
    wstring_convert<codecvt_utf8<wchar_t>> converter;
    return converter.from_bytes(str);
}

string convertWStringToString(const wstring &wstr)
{
    wstring_convert<codecvt_utf8<wchar_t>> converter;
    return converter.to_bytes(wstr);
}

void get_input(string &input, string &key, string &iv, int &option)
{
    wstring winput, wkey, wiv;
    wcout << L"Do you want encrypt or decrypt " << endl;
    wcout << "1) Encrypt" << endl; 
    wcout << "2) Decrypt" << endl; 
    wcout << "Please confirm your choice: " ;
    wcin >> option;

    // Nhập input
    switch(option)
    {
        case 1:
            wcout << L"Enter plaintext (Vietnamese is available): ";
            fflush(stdin);
            getline(wcin, winput);
            input = convertWStringToString(winput);
            break;

        case 2:
            wcout << L"Enter ciphertext: ";
            fflush(stdin);
            getline(wcin, winput);
            input = convertWStringToString(winput);
            break;

        default:
            wcout << L"Error!!! Please choose again!!!" << endl;
            break;
    }

    // Nhập key
    wcout << L"Enter secret key (32 byte): ";
    fflush(stdin);
    getline(wcin, wkey);
    key = convertWStringToString(wkey);

    // Nhập IV
    wcout << L"Enter IV (16 byte): ";
    fflush(stdin);
    getline(wcin, wiv);
    iv = convertWStringToString(wiv);
}
