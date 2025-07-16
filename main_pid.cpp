#include "mpc/pso/mqrpmt_private_id.hpp"
#include "crypto/setup.hpp"

enum class FileType { Bin, Csv, Unspecified };

std::ifstream::pos_type filesize(std::ifstream& file)
{
    auto pos = file.tellg();
    file.seekg(0, std::ios_base::end);
    auto size = file.tellg();
    file.seekg(pos, std::ios_base::beg);
    return size;
}

bool isHexBlock(const std::string& buff)
{
    if (buff.size() != 32)
        return false;
    auto ret = true;
    for (uint64_t i = 0; i < 32; ++i)
        ret &= (bool)std::isxdigit(buff[i]);
    return ret;
}

block hexToBlock(const std::string& buff)
{
    assert(buff.size() == 32);

    std::array<uint8_t, 16> vv;
    char b[3];
    b[2] = 0;

    for (uint64_t i = 0; i < 16; ++i)
    {
        b[0] = buff[2 * i + 0];
        b[1] = buff[2 * i + 1];
        vv[15 - i] = (char)strtol(b, nullptr, 16);;
    }
    block ret;

    memcpy(&ret, vv.data(), sizeof(block));
    return ret;
}


std::vector<block> readSet(const std::string& path, FileType ft) {
    std::vector<block> ret;
    if (ft == FileType::Bin)
    {
        std::ifstream file(path, std::ios::binary | std::ios::in);
        if (file.is_open() == false)
            throw std::runtime_error("failed to open file: " + path);
        auto size = filesize(file);
        if (size % 16)
            throw std::runtime_error("Bad file size. Expecting a binary file with 16 byte elements");

        ret.resize(size / 16);
        file.read((char*)ret.data(), size);
    }
    else if (ft == FileType::Csv)
    {
        std::ifstream file(path, std::ios::in);
        if (file.is_open() == false)
            throw std::runtime_error("failed to open file: " + path);
        std::string buffer;
        while (std::getline(file, buffer))
        {
            // if the input is already a 32 char hex 
            // value, just parse it as is.
            if (isHexBlock(buffer))
            {
                ret.push_back(hexToBlock(buffer));
            }
            else
            {
                ret.push_back(Hash::StringToBlock(buffer));
            }
        }
    }
    else
    {
        throw std::runtime_error("unknown file type");
    }

    return ret;
}


int main(int argc, char** argv)
{
    /* if (argc < 3)
    {
        std::cout << "Usage: " << argv[0] << " <set> [file_type]" << std::endl;
        std::cout << "file_type: bin or csv (default: bin)" << std::endl;
        return 1;
    }

    FileType file_type = FileType::Bin;
    if (argc == 4)
    {
        if (std::string(argv[3]) == "csv")
            file_type = FileType::Csv;
        else if (std::string(argv[3]) != "bin")
            throw std::runtime_error("unknown file type");
    } */
    CRYPTO_Initialize(); 

    std::vector<block> input = readSet(argv[1], FileType::Csv);

    std::cout << "Private-ID begins >>>" << std::endl; 

    PrintSplitLine('-');  
    std::cout << "generate or load public parameters and test case" << std::endl;

    // generate pp (must be same for both server and client)
    std::string pp_filename = "PrivateID.pp"; 
    mqRPMTPrivateID::PP pp; 
 
    if(!FileExist(pp_filename)){
        std::cout << pp_filename << " does not exist" << std::endl;
        size_t computational_security_parameter = 128;         
        size_t statistical_security_parameter = 40; 
        size_t LOG_SENDER_ITEM_NUM = 7;
        size_t LOG_RECEIVER_ITEM_NUM = 7;  
        size_t LOG_PRF_INPUT_LEN = std::max(LOG_RECEIVER_ITEM_NUM, LOG_SENDER_ITEM_NUM); // set OPRF input length
        pp = mqRPMTPrivateID::Setup(LOG_PRF_INPUT_LEN, computational_security_parameter, statistical_security_parameter, 
                              LOG_SENDER_ITEM_NUM, LOG_RECEIVER_ITEM_NUM); 
        mqRPMTPrivateID::SavePP(pp, pp_filename); 
    }
    else{
        std::cout << pp_filename << " already exists" << std::endl;
        mqRPMTPrivateID::FetchPP(pp, pp_filename); 
    }

    std::string party;
    std::cout << "please select your role between sender and receiver (hint: first start sender, then start receiver) ==> ";  
    std::getline(std::cin, party); // first the server, then the client
    PrintSplitLine('-'); 

    size_t ITEM_LEN = pp.oprf_part.RANGE_SIZE; // byte length of each item
    
    if(party == "sender"){
        NetIO server_io("server", "", 8080);
        std::tuple<std::vector<std::vector<uint8_t>>, std::vector<std::vector<uint8_t>>> result = mqRPMTPrivateID::Send(server_io, pp, input, ITEM_LEN);
        std::vector<std::vector<uint8_t>> vec_union_id = std::get<0>(result);
        std::vector<std::vector<uint8_t>> vec_X_id = std::get<1>(result);
        std::cout << "Sender's ID (union) >>>" << std::endl;
        for (int i = 0; i < vec_union_id.size(); ++i) 
            Block::PrintBlock(*(block*)&vec_union_id[i][0]);

        std::cout << "Sender's ID (X) >>>" << std::endl;
        for (int i = 0; i < vec_X_id.size(); ++i)
            Block::PrintBlock(*(block*)&vec_X_id[i][0]);
    }
    
    if(party == "receiver"){
        NetIO client_io("client", "127.0.0.1", 8080);        
        std::tuple<std::vector<std::vector<uint8_t>>, std::vector<std::vector<uint8_t>>> result = mqRPMTPrivateID::Receive(client_io, pp, input, ITEM_LEN);
        std::vector<std::vector<uint8_t>> vec_union_id = std::get<0>(result);
        std::vector<std::vector<uint8_t>> vec_Y_id = std::get<1>(result);
        std::cout << "Receiver's ID (union) >>>" << std::endl;
        for (int i = 0; i < vec_union_id.size(); ++i) 
            Block::PrintBlock(*(block*)&vec_union_id[i][0]);
        
        std::cout << "Receiver's ID (Y) >>>" << std::endl;
        for (int i = 0; i < vec_Y_id.size(); ++i)
            Block::PrintBlock(*(block*)&vec_Y_id[i][0]);
        
        /* for (int i = 0; i < vec_union_id.size(); ++i) {
            for (int j = 0; j < vec_union_id[i].size(); ++j) {
                std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)vec_union_id[i][j];
            }
        } */
    } 

    CRYPTO_Finalize();   
    
    return 0; 
}
