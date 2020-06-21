#include "extractor.hpp"
#include "variables.hpp"
#include "packet_handler.hpp"
#include <iostream>
#include <pcap.h>
#include <pthread.h>
#include <condition_variable>
#include <mutex>
#include <boost/program_options.hpp>
using namespace std;

std::condition_variable cond;
static bool flow_is_end = false;
static pcap_t *handlers[2];

static void* sniff_interface(void* ptr) {
    //bool *is_server = (bool *)ptr;
    Host *host = (Host*) ptr;
    char *dev;
    pcap_t *handler;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (*host == Host::Server) {
        //dev = server_interface.c_str();
        handler = pcap_open_live(server_interface.c_str(), BUFSIZ, 0, 1, errbuf);
        server_pcap_t = handler;
    } else if (*host == Host::Client){
        //dev = client_interface.c_str();
        handler = pcap_open_live(client_interface.c_str(), BUFSIZ, 0, 1, errbuf);
        client_pcap_t = handler;
    } else {
        std::cerr << "Can't decide the nif is client or server!" << std::endl;
    }

    if (handler == NULL) {
      cout << "pcap_open_live() failed: " << errbuf << endl;
      return NULL;
    }

    struct pcap_pkthdr *pkt_header;   
    u_char *pkt_data;         
    int retval;
    cout << "----------- Start sniffing packet! ------------" << std::endl;
    if(*host == Host::Server) {
        while ((retval = pcap_next_ex(handler, &pkt_header, (const u_char **) &pkt_data)) >= 0) {
            u_int packet_size= pkt_header->caplen;
            MyPacket * p_packet = new MyPacket;
            memcpy(p_packet->packet_buf, (u_char*)pkt_data, packet_size);

            /*for (int i = 0; i < sizeof(u_char) * packet_size; ++i){
                if (p_packet->packet_buf[i] != pkt_data[i]) std::cerr <<"copy errer" <<std::endl;
                // TODO: if nothing's wrong, delete this
                p_packet->packet_buf[i] = pkt_data[i];
            }*/

            p_packet->pkthdr.ts = pkt_header->ts;
            p_packet->pkthdr.caplen = pkt_header->caplen;
            p_packet->pkthdr.len = pkt_header->len;
            //captured_sif_packets.push(p_packet);
            captured_sif_packets.enqueue(p_packet);
        }
    } else if (*host == Host::Client) {
        while ((retval = pcap_next_ex(handler, &pkt_header, (const u_char **) &pkt_data)) >= 0) {
            //std::cout << "captured a packet on cif!" <<std::endl;
            u_int packet_size= pkt_header->caplen;
            MyPacket * p_packet = new MyPacket;
            memcpy(p_packet->packet_buf, (u_char*)pkt_data, packet_size);

            //for (int i = 0; i < sizeof(u_char) * packet_size + 1; ++i){
            //    if (p_packet->packet_buf[i] != pkt_data[i]) std::cerr <<"copy errer" <<std::endl;
                // TODO: if nothing's wrong, delete this
            //    p_packet->packet_buf[i] = pkt_data[i];
           // }

            p_packet->pkthdr.ts = pkt_header->ts;
            p_packet->pkthdr.caplen = pkt_header->caplen;
            p_packet->pkthdr.len = pkt_header->len;
            captured_cif_packets.enqueue(p_packet);
        }
    }
    pcap_close(handler);
}

static void* handle_packets(void* ptr) {
    Host *host = (Host*) ptr;

    //struct pcap_pkthdr *pkt_header;   
    //u_char *pkt_data;         
    int retval;
    std::cout << "----------- Start handling packet! ------------" << std::endl;
    
    bool is_end = false;
    //captured_cif_packets.clear(); 
    //captured_sif_packets.clear();
    while(!captured_cif_packets.is_empty()){
            MyPacket * p_packet = captured_cif_packets.dequeue();
            delete p_packet;
    }
    while(!captured_sif_packets.is_empty()){
            MyPacket * p_packet = captured_sif_packets.dequeue();
            delete p_packet;
    }
    while(!is_end){
        if(!captured_cif_packets.is_empty()){
            MyPacket * p_packet = captured_cif_packets.dequeue();
            is_end = client_packet_handler(&(p_packet->pkthdr), p_packet->packet_buf, NULL);
            delete p_packet;
        } else
        if(!captured_sif_packets.is_empty()){
            MyPacket * p_packet = captured_sif_packets.dequeue();
            is_end = server_packet_handler(&(p_packet->pkthdr), p_packet->packet_buf, NULL);
            delete p_packet;
        }
    }
    /*
    if(*host == Host::Server) {
        while (!flow_is_end) {
            MyPacket * p_packet = captured_sif_packets.dequeue();
            is_end = server_packet_handler(&(p_packet->pkthdr), p_packet->packet_buf, NULL);
            if (is_end) break;
        }
    } else if (*host == Host::Client) {
        while (!flow_is_end) {
            MyPacket * p_packet = captured_cif_packets.dequeue();
            is_end = client_packet_handler(&(p_packet->pkthdr), p_packet->packet_buf, NULL);
            if (is_end) break;
        }   
    } 
    flow_is_end = true;
    */
    cond.notify_one();
}

static void smain() {
    //char *sdev,*cdev;
    //std::vector<pthread_t*> threads;
    const char * sdev = server_interface.c_str();
    const char * cdev = client_interface.c_str();
    Host server = Host::Server;
    Host client = Host::Client;
    pthread_t* cif_cap_thread = new pthread_t;
    pthread_t* sif_cap_thread = new pthread_t;

    // create thread
    pthread_create(sif_cap_thread, NULL, &sniff_interface, (void *) &server);
    pthread_create(cif_cap_thread, NULL, &sniff_interface, (void *) &client);

    while (!server_filename_queue.empty() && !client_filename_queue.empty()) {
        auto server_name = server_filename_queue.front();
        auto client_name = client_filename_queue.front();
        auto queue_name = queue_filename_queue.front();
        queue_filename = queue_name;

        server_filename_queue.pop();
        client_filename_queue.pop();
        queue_filename_queue.pop();
        
        server_filename_queue.push(server_name);
        client_filename_queue.push(client_name);
        queue_filename_queue.push(queue_name);
        extract_trace(server_name, client_name);
        for (int i = 0; i < repeat_times; ++i){
            flow_is_end = false;
            packet_handler_initiate();
            
            //pthread_t* client_thread = new pthread_t;
            pthread_t* server_thread = new pthread_t;
            pthread_create(server_thread, NULL, &handle_packets, (void *) &server);
            //pthread_create(client_thread, NULL, &handle_packets, (void *) &client);
            
            /*
            std::mutex mtx;
            std::unique_lock<std::mutex> lck(mtx);
            while(true) {
                cond.wait(lck);
                if (flow_is_end) break;
            }
            pthread_cancel(*server_thread);
            pthread_cancel(*client_thread);*/
            //server_thread.Destroy();
            //client_thread.Destroy();
            /// wait for threads to terminate.
            pthread_join(*server_thread, NULL);
            //pthread_join(*client_thread, NULL);
            delete server_thread;
            //delete client_thread;
        }
    }
    pthread_cancel(*sif_cap_thread);
    pthread_cancel(*cif_cap_thread);
}


/// Print the explanatory string of an exception. If the exception is nested,
/// recurses to print the explanatory of the exception it holds.
static void recursive_print_exception(const std::exception& e)
{
    std::cerr << e.what() << std::endl;
    try {
        std::rethrow_if_nested(e);
    } catch(const std::exception& e) {
        recursive_print_exception(e);
    } catch(...) {}
}

/// Print the type of the exception and its message.
template <typename T>
void show_exception_message(T &e) {
    auto exception_type = boost::typeindex::type_id<T>().pretty_name();
    std::cerr << "Caught an exception of type ["
              << exception_type << "]" << std::endl;
    std::cerr << "Exception message:" << std::endl;
    recursive_print_exception(e);
}

static void parse_option(int argc, char **argv) {
    namespace po = boost::program_options;
    po::options_description all_opts("Options");
    all_opts.add_options()
        ("help", "Produce help message.\n")
        ("drtt", "Delay RTT.\n")
        ("auto", po::value<std::string>(),
            "Circularly use all the traces.\n")
        ("test", po::value<std::string>(),
            "Test functions.\n")
        ("trace", po::value<std::string>(),
            "Trace folder. "
            "Defaultly set to ./trace/")
        ("no", po::value<std::string>(),
            "NO. of trace pair.")
        ("server", po::value<std::string>(),
            "Server CSV (from pcap). "
            "Defaultly set to 1s.csv\n")
        ("client", po::value<std::string>(),
            "Client CSV (from pcap). "
            "Defaultly set to 1c.csv\n")
        ("sif", po::value<std::string>(),
            "Name of the interface connected to server."
            "e.g. eth0 .\n")
        ("cif", po::value<std::string>(),
            "Name of the interface connected to client."
            "e.g. eth1 .\n")
        ("sip", po::value<std::string>(),
            "Server IP (e.g. 106.58.5.123).\n")
        ("tsip", po::value<std::string>(),
            "Server IP (e.g. 106.58.5.123).\n")
        ("tcip", po::value<std::string>(),
            "Client IP (e.g. 106.58.5.124).\n")
        ("repeat", po::value<int>()->default_value(1),
            "repeating times for each trace."
            "Default to 1.\n")
        ("lte", po::value<std::string>(),
            "Mobileinsight XML file.\n");
    /// Build the option map and parse options.
    po::variables_map vm;
    po::store(po::command_line_parser(argc, argv).
        options(all_opts).run(), vm);
    po::notify(vm);

    /// If --help or -h is set, show the help message and exit.
    if (vm.count("help")) {
        std::cout << "Usage: " + std::string(argv[0])
                  << " [options] [input_file ...]" << std::endl;
        std::cout << "If no input file is provided, it reads from stdin."
                  << std::endl;
        std::cout << all_opts << std::endl;
        exit(0);
    }

    if (vm.count("drtt")) {
        std::cout << "delay RTT func is on!" << std::endl;
        rtt_delay = true;
    } else {
        std::cout << "delay RTT func is off!" << std::endl;
        rtt_delay = false;
    }

    if (vm.count("repeat")) {
        repeat_times = vm["repeat"].as<int>();
    } 

    if (vm.count("sif")) {
        server_interface = vm["sif"].as<std::string>();
    } else {
        server_interface = "ens8";
    }

    if (vm.count("cif")) {
        client_interface = vm["cif"].as<std::string>();
    } else {
        client_interface = "ens7";
    }

    if (vm.count("sip")) {
        // std::string = vm["sip"].as<std::string>();
        stringstream stream(vm["sip"].as<std::string>());
        string _sub; 
        while (getline(stream, _sub, ','))
            server_ip_vector.push_back(_sub);
    } else {
        server_ip_vector.push_back("10.4.112.4");
        server_ip_vector.push_back("172.17.0.4");
        server_ip_vector.push_back("172.17.0.16");
        server_ip_vector.push_back("106.54.147.34");
        server_ip_vector.push_back("106.54.147.38");
    }

    if (vm.count("tsip")) {
        // std::string = vm["sip"].as<std::string>();
        stringstream stream(vm["tsip"].as<std::string>());
        string _sub; 
        while (getline(stream, _sub, ','))
            server_ip_vector.push_back(_sub);
    } else {
        server_ip = "10.4.112.4";
    }

    if (vm.count("tcip")) {
        client_ip = vm["tcip"].as<std::string>();
    } else {
        client_ip = "10.4.96.4";
    }
    std::string folder;
    if (vm.count("folder")) {
        folder = vm["folder"].as<std::string>();
        if (folder[folder.size()-1] != '/') {
            folder += "/";
        }
    } else {
        folder = "./trace/";
    }

    if (vm.count("no")) {
        const auto &no = vm["no"].as<std::string>();
        auto server_name = folder + no + "s.csv";
        auto client_name = folder + no + "c.csv";
        
        server_filename_queue.push(server_name);
        client_filename_queue.push(client_name);
        queue_filename_queue.push("./tmp/" + no + "c.csv");
        //server_filename_vector.emplace_back(std::move(server_name));
        //client_filename_vector.emplace_back(std::move(client_name));       
        
    } else if (vm.count("server") && vm.count("client")) {
        server_filename_queue.push(folder + vm["server"].as<std::string>());
        client_filename_queue.push(folder + vm["client"].as<std::string>()); 
        queue_filename_queue.push("./tmp/" + vm["client"].as<std::string>());       
    } else if (vm.count("auto")) {
        int trace_count = std::stoi(vm["auto"].as<std::string>());
        for (int i = 1; i <= trace_count; ++i){
            std::string no = std::to_string(i);
            auto server_name = folder + no + "s.csv";
            auto client_name = folder + no + "c.csv";
            server_filename_queue.push(server_name);
            client_filename_queue.push(client_name);
            queue_filename_queue.push("./tmp/" + no + "c.csv");
        }
    } else{
        auto server_name = folder + "1s.csv";
        auto client_name = folder + "1c.csv";
        server_filename_queue.push(server_name);
        client_filename_queue.push(client_name);
    }
}

int main(int argc, char **argv) {
    try{
        parse_option(argc, argv);
        smain();
    } catch (...) {
        std::cerr << "Caught an unknown exception!" << std::endl;
    }
    return 0;
}