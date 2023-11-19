#include "aes_modes.h"
#include <chrono>
#include <ctime>

int main()
{
    supportVietnamese();

    int action_option;
    int mode_option;
    int plain_option;
    int cipher_option;
    int key_option;
    int iv_option;
    char recover_option;
    int key_size = AES::DEFAULT_KEYLENGTH, iv_size = AES::BLOCKSIZE;

    string plain, cipher, recovered, file_name, input_key, input_iv;

    cout << "--------------------------------- AES -------------------------------------" << endl;
    cout << "Nhập mode (1: ECB, 2: CBC, 3: CFB, 4: OFB, 5: CTR, 6: XTS, 7: CCM, 8: GCM): ";
    cin >> mode_option;

    if (mode_option == 6)
    {
        key_size = 32;
    }
    
    if (mode_option == 7)
    {
        iv_size = 12;
    }

    // Initialize random generator, key and IV
    AutoSeededRandomPool prng;
    CryptoPP::byte key[key_size];
    CryptoPP::byte iv[iv_size];

    cout << "Nhập lựa chọn (1: Encrypt, 2: Decrypt): ";
    cin >> action_option;

    switch(action_option)
    {
        case 1:
            cout << "Nhập lựa chọn lấy plaintext (1: Màn hình, 2: File): ";
            cin >> plain_option;

            switch(plain_option)
            {
                case 1:
                    cin.ignore();
                    getline(cin, plain);
                    break;

                case 2:
                    cout << "Nhập tên file: ";
                    cin >> file_name;
                    FileSource(file_name.data(), true, new StringSink(plain));
                    break;

                default:
                    cout << "Không có lựa chọn này! Vui lòng nhập lại!";
                    return 0;
            }
            
            cout << "Nhập lựa chọn lấy key (1: Ngẫu nhiên, 2: Màn hình, 3: File): ";
            cin >> key_option;

            switch(key_option)
            {
                case 1:
                    prng.GenerateBlock(key, sizeof(key));

                    // Prepare to print key
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(input_key)));

                    // Save key to file
                    StringSource(key, sizeof(key), true, new FileSink("aes_key.key", sizeof(key)));
                    break;

                case 2:
                    cin >> input_key; // key is in hex
                    StringSource(input_key, true, new HexDecoder(new ArraySink(key, sizeof(key))));

                    // Save key to file
                    StringSource(key, sizeof(key), true, new FileSink("aes_key.key", sizeof(key)));
                    break;

                case 3:
                    file_name.clear();
                    cout << "Nhập tên file: ";
                    cin >> file_name;
                    FileSource(file_name.data(), true, new ArraySink(key, sizeof(key)));
                    break;

                default:
                    cout << "Không có lựa chọn này! Vui lòng nhập lại!";
                    return 0;
            }

            if (mode_option == 1)
            {
                cipher = ecb_encrypt(plain, key);
            }
            else
            {
                cout << "Nhập lựa chọn lấy IV (1: Ngẫu nhiên, 2: Màn hình, 3: File): ";
                cin >> iv_option;

                switch(iv_option)
                {
                    case 1:
                        prng.GenerateBlock(iv, sizeof(iv));

                        // Prepare to print iv
                        StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(input_iv)));

                        // Save key to file
                        StringSource(iv, sizeof(iv), true, new FileSink("aes_iv.key", sizeof(iv)));
                        break;

                    case 2:
                        cin >> input_iv; // key is in hex
                        StringSource(input_iv, true, new HexDecoder(new ArraySink(iv, sizeof(iv))));

                        // Save key to file
                        StringSource(iv, sizeof(iv), true, new FileSink("aes_iv.key", sizeof(iv)));
                        break;

                    case 3:
                        file_name.clear();
                        cout << "Nhập tên file: ";
                        cin >> file_name;
                        FileSource(file_name.data(), true, new ArraySink(iv, sizeof(iv)));
                        break;

                    default:
                        cout << "Không có lựa chọn này! Vui lòng nhập lại!";
                        return 0;
                }

                switch(mode_option)
                {
                    case 2:
                        cipher = cbc_encrypt(plain, key, iv);
                        break;

                    case 3:
                        cipher = cfb_encrypt(plain, key, iv);
                        break;

                    case 4:
                        cipher = ofb_encrypt(plain, key, iv);
                        break;

                    case 5:
                        cipher = ctr_encrypt(plain, key, iv);
                        break;

                    case 6:
                        cipher = xts_encrypt(plain, key, iv);
                        break;
                    
                    case 7:
                        cipher = ccm_encrypt(plain, key, iv);
                        break;

                    case 8:
                        cipher = gcm_encrypt(plain, key, iv);
                        break;
                }
            }

            cout << "Plaintext: " << plain << endl;
            cout << "Key: " << input_key << endl;

            if (mode_option > 1)
            {
                cout << "IV: " << input_iv << endl;
            }

            cout << "Ciphertext: " << cipher << endl;
            // Decrypt instantly
            cout << "Bạn có muốn khôi phục dữ liệu? (y|n): ";
            cin >> recover_option;
            CryptoPP::StringSource(cipher, true, new FileSink("cipher.txt", false));
            switch(recover_option)
            {
                case 'y':
                    switch(mode_option)
                    {
                        case 1:
                            recovered = ecb_decrypt(cipher, key);
                            break;

                        case 2:
                            recovered = cbc_decrypt(cipher, key, iv);
                            break;

                        case 3:
                            recovered = cfb_decrypt(cipher, key, iv);
                            break;

                        case 4:
                            recovered = ofb_decrypt(cipher, key, iv);
                            break;

                        case 5:
                            recovered = ctr_decrypt(cipher, key, iv);
                            break;

                        case 6:
                            recovered = xts_decrypt(cipher, key, iv);
                            break;

                        case 7:
                            recovered = ccm_decrypt(cipher, key, iv);
                            break;

                        case 8:
                            recovered = gcm_decrypt(cipher, key, iv);
                            break;
                    }

                    cout << "Recovered text: " << recovered << endl;
                    break;

                case 'n':
                    break;
            }
            
            break;

        case 2:
            cout << "Nhập lựa chọn lấy ciphertext (1: Màn hình, 2: File): ";
            cin >> cipher_option;

            switch(cipher_option)
            {
                case 1:
                    cin.ignore();
                    getline(cin, cipher); // ciphertext must in hex
                    break;

                case 2:
                    cout << "Nhập tên file: ";
                    cin >> file_name;
                    FileSource(file_name.data(), true, new StringSink(cipher));
                    break;

                default:
                    cout << "Không có lựa chọn này! Vui lòng nhập lại!";
                    return 0;
            }
            
            cout << "Nhập lựa chọn lấy key (1: Ngẫu nhiên, 2: Màn hình, 3: File): ";
            cin >> key_option;

            switch(key_option)
            {
                case 1:
                    prng.GenerateBlock(key, sizeof(key));

                    // Prepare to print key
                    StringSource(key, sizeof(key), true, new HexEncoder(new StringSink(input_key)));

                    // Save key to file
                    StringSource(key, sizeof(key), true, new FileSink("aes_key.key", sizeof(key)));
                    break;

                case 2:
                    cin >> input_key; // key is in hex
                    StringSource(input_key, true, new HexDecoder(new ArraySink(key, sizeof(key))));

                    // Save key to file
                    StringSource(key, sizeof(key), true, new FileSink("aes_key.key", sizeof(key)));
                    break;

                case 3:
                    file_name.clear();
                    cout << "Nhập tên file: ";
                    cin >> file_name;
                    FileSource(file_name.data(), true, new ArraySink(key, sizeof(key)));
                    break;

                default:
                    cout << "Không có lựa chọn này! Vui lòng nhập lại!";
                    return 0;
            }

            if (mode_option == 1)
            {
                plain = ecb_decrypt(cipher, key);
            }
            else
            {
                cout << "Nhập lựa chọn lấy IV (1: Ngẫu nhiên, 2: Màn hình, 3: File): ";
                cin >> iv_option;

                switch(iv_option)
                {
                    case 1:
                        prng.GenerateBlock(iv, sizeof(iv));

                        // Prepare to print iv
                        StringSource(iv, sizeof(iv), true, new HexEncoder(new StringSink(input_iv)));

                        // Save key to file
                        StringSource(iv, sizeof(iv), true, new FileSink("aes_iv.key", sizeof(iv)));
                        break;

                    case 2:
                        cin >> input_iv; // key is in hex
                        StringSource(input_iv, true, new HexDecoder(new ArraySink(iv, sizeof(iv))));

                        // Save key to file
                        StringSource(iv, sizeof(iv), true, new FileSink("aes_iv.key", sizeof(iv)));
                        break;

                    case 3:
                        file_name.clear();
                        cout << "Nhập tên file: ";
                        cin >> file_name;
                        FileSource(file_name.data(), true, new ArraySink(iv, sizeof(iv)));
                        break;

                    default:
                        cout << "Không có lựa chọn này! Vui lòng nhập lại!";
                        return 0;
                }

                switch(mode_option)
                {
                    case 2:
                        plain = cbc_decrypt(cipher, key, iv);
                        break;

                    case 3:
                        plain = cfb_decrypt(cipher, key, iv);
                        break;

                    case 4:
                        plain = ofb_decrypt(cipher, key, iv);
                        break;

                    case 5:
                        plain = ctr_decrypt(cipher, key, iv);
                        break;

                    case 6:
                        plain = xts_decrypt(cipher, key, iv);
                        break;
                    
                    case 7:
                        plain = ccm_decrypt(cipher, key, iv);
                        break;

                    case 8:
                        plain = gcm_decrypt(cipher, key, iv);
                        break;
                }
            }

            cout << "Ciphertext: " << cipher << endl;
            cout << "Key: " << input_key << endl;

            if (mode_option > 1)
            {
                cout << "IV: " << input_iv << endl;
            }

            cout << "Plaintext: " << plain << endl;
            break;
    }

    // Calculate running time

    if (action_option == 1)
    {
        double time_run = 0;

        for (int i = 0; i < 10000; i++)
        {
            clock_t begin = clock();

            switch(mode_option)
            {
                case 1:
                    ecb_encrypt(plain, key);
                    break;

                case 2:
                    cbc_encrypt(plain, key, iv);
                    break;

                case 3:
                    cfb_encrypt(plain, key, iv);
                    break;

                case 4:
                    ofb_encrypt(plain, key, iv);
                    break;

                case 5:
                    ctr_encrypt(plain, key, iv);
                    break;

                case 6:
                    xts_encrypt(plain, key, iv);
                    break;
                    
                case 7:
                    ccm_encrypt(plain, key, iv);
                    break;

                case 8:
                    gcm_encrypt(plain, key, iv);
                    break;
            }

            clock_t end = clock();
            double time_per_round = (double)(end - begin) / CLOCKS_PER_SEC;
            time_run += time_per_round;
        }
        
        cout << "Thời gian trung bình mỗi vòng sau 10000 vòng: " << time_run / 10000 << 's' << endl;
    }
    else
    {
        double time_run = 0;
        
        for (int i = 0; i < 10000; i++)
        {
            clock_t begin = clock();

            switch(mode_option)
            {
                case 1:
                    ecb_decrypt(cipher, key);
                    break;

                case 2:
                    cbc_decrypt(cipher, key, iv);
                    break;

                case 3:
                    cfb_decrypt(cipher, key, iv);
                    break;

                case 4:
                    ofb_decrypt(cipher, key, iv);
                    break;

                case 5:
                    ctr_decrypt(cipher, key, iv);
                    break;

                case 6:
                    xts_decrypt(cipher, key, iv);
                    break;
                    
                case 7:
                    ccm_decrypt(cipher, key, iv);
                    break;

                case 8:
                    gcm_decrypt(cipher, key, iv);
                    break;
            }

            clock_t end = clock();
            double time_per_round = (double)(end - begin) / CLOCKS_PER_SEC;
            time_run += time_per_round;
        }

        cout << "Thời gian trung bình mỗi vòng sau 10000 vòng: " << time_run / 10000 << 's' << endl;
    }

    cout << "-------------------------- Chương trình kết thúc --------------------------" << endl;
    return 0;
}