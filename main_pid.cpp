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

bool hasSuffix(std::string const& value, std::string const& ending)
{
    if (ending.size() > value.size()) return false;
    return std::equal(ending.rbegin(), ending.rend(), value.rbegin());
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


std::vector<block> readSet(const std::string& path) {
    std::vector<block> ret;
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
    return ret;
}

void padInput(std::vector<block>& input, size_t ITEM_LEN)
{
}

void writeOutput(std::string outPath, const std::tuple<std::vector<std::vector<uint8_t>>, std::vector<std::vector<uint8_t>>>& output)
{
    std::ofstream file;

    file.open(outPath, std::ios::out | std::ios::trunc);

    if (file.is_open() == false)
        throw std::runtime_error("failed to open the output file: " + outPath);

    std::vector<std::vector<uint8_t>> vec_union_id = std::get<0>(output);
    std::vector<std::vector<uint8_t>> vec_party_id = std::get<0>(output);

    for (uint64_t i = 0; i < vec_party_id.size(); ++i)
    {
        file << *(block*)&vec_union_id[i][0] << "," << *(block*)&vec_party_id[i][0] << std::endl;
    }

    // If the union set is larger than the party set which is very probable, we write the rest of the union set without the party set.
    for (uint64_t i = vec_party_id.size(); i < vec_union_id.size(); ++i)
    {
        file << *(block*)&vec_union_id[i][0] << "," << std::endl;
    }
}


int main(int argc, char** argv)
{
    if (argc != 2)
    {
        std::cout << "Usage: " << argv[0] << " <set_file>" << std::endl;
        return 1;
    }

    CRYPTO_Initialize(); 

    std::vector<block> input = readSet(argv[1]);

    std::cout << "Private-ID begins >>>" << std::endl; 

    PrintSplitLine('-');  
    std::cout << "Loading public parameters if they exist" << std::endl;

    // generate pp (must be same for both server and client)
    std::string pp_filename = "PrivateID.pp"; 
    mqRPMTPrivateID::PP pp;
    std::cout << "Use file for public parameters if available? (y/n) ==> ";
    std::string use_file_str;
    std::getline(std::cin, use_file_str);

    if(!FileExist(pp_filename) || use_file_str != "y"){
        std::cout << pp_filename << " being created" << std::endl;
        size_t computational_security_parameter = 128;         
        size_t statistical_security_parameter = 40; 
        size_t log_sender_item_num;
        size_t log_receiver_item_num;
        
        std::cout << "Please input log_sender_item_num and log_receiver_item_num. Both must be >= 7 (e.g., 10 10) ==> ";
        std::cin >> log_sender_item_num >> log_receiver_item_num;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
        if(log_sender_item_num < 7 || log_receiver_item_num < 7){
            std::cerr << "log_sender_item_num and log_receiver_item_num must be >= 7" << std::endl; 
            exit(1); 
        }

        size_t log_prf_input_len = std::max(log_receiver_item_num, log_sender_item_num); // set OPRF input length
        pp = mqRPMTPrivateID::Setup(log_prf_input_len, computational_security_parameter, statistical_security_parameter, 
                              log_sender_item_num, log_receiver_item_num); 
        mqRPMTPrivateID::SavePP(pp, pp_filename); 
    }
    else{
        std::cout << pp_filename << " already exists" << std::endl;
        mqRPMTPrivateID::FetchPP(pp, pp_filename); 
    }

    std::string party;
    std::cout << "Please select your role between sender and receiver (hint: first start sender, then start receiver) ==> ";  
    std::getline(std::cin, party); // first the server, then the client
    PrintSplitLine('-'); 

    size_t ITEM_LEN = pp.oprf_part.RANGE_SIZE; // byte length of each item
    
    if(party == "sender"){
        int port;
        std::cout << "Please input the port number for the server (e.g., 8080) ==> ";
        std::cin >> port;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        NetIO server_io("server", "", port);
        std::tuple<std::vector<std::vector<uint8_t>>, std::vector<std::vector<uint8_t>>> result = mqRPMTPrivateID::Send(server_io, pp, input, ITEM_LEN);
        std::vector<std::vector<uint8_t>> vec_union_id = std::get<0>(result);
        std::vector<std::vector<uint8_t>> vec_X_id = std::get<1>(result);

        /* std::sort(vec_union_id.begin(), vec_union_id.end());
        std::sort(vec_X_id.begin(), vec_X_id.end()); */

        std::cout << "Sender's ID (union) >>>" << std::endl;
        for (int i = 0; i < vec_union_id.size(); ++i) 
            Block::PrintBlock(*(block*)&vec_union_id[i][0]);

        std::cout << "Sender's ID (X) >>>" << std::endl;
        for (int i = 0; i < vec_X_id.size(); ++i)
            Block::PrintBlock(*(block*)&vec_X_id[i][0]);
    }
    
    if(party == "receiver"){
        std::string address;
        int port;
        std::cout << "Please input the server's address and port number (e.g., 127.0.0.1 8080) ==> ";
        std::cin >> address >> port;
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        NetIO client_io("client", address, port);        
        std::tuple<std::vector<std::vector<uint8_t>>, std::vector<std::vector<uint8_t>>> result = mqRPMTPrivateID::Receive(client_io, pp, input, ITEM_LEN);
        std::vector<std::vector<uint8_t>> vec_union_id = std::get<0>(result);
        std::vector<std::vector<uint8_t>> vec_Y_id = std::get<1>(result);

        /* std::sort(vec_union_id.begin(), vec_union_id.end());
        std::sort(vec_Y_id.begin(), vec_Y_id.end()); */

        std::cout << "Receiver's ID (union) >>>" << std::endl;
        for (int i = 0; i < vec_union_id.size(); ++i) 
            Block::PrintBlock(*(block*)&vec_union_id[i][0]);
        
        std::cout << "Receiver's ID (Y) >>>" << std::endl;
        for (int i = 0; i < vec_Y_id.size(); ++i)
            Block::PrintBlock(*(block*)&vec_Y_id[i][0]);
    } 

    CRYPTO_Finalize();   
    
    return 0; 
}
