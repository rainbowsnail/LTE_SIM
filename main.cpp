#include "extractor.hpp"
#include "variables.hpp"
#include "packet_handler.hpp"
#include <iostream>
#include <pcap.h>
#include <pthread.h>
#include <boost/program_options.hpp>
using namespace std;
 
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
    //char *dev = (char * )dev_name;

    //dev = pcap_lookupdev(errbuf);
    //if (dev == NULL) {
    //    cout << "pcap_lookupdev() failed: " << errbuf << endl;
    //    return 1;
    //}
    //handler = pcap_open_live(dev, BUFSIZ, 0, 1, errbuf);
    if (handler == NULL) {
      cout << "pcap_open_live() failed: " << errbuf << endl;
      return NULL;
    }

    //if (pcap_loop(descr, -1, server_packet_handler, NULL) < 0) {
    //  cout << "pcap_loop() failed: " << pcap_geterr(descr);
    //  return 1;
    //}
    struct pcap_pkthdr *pkt_header;   
    u_char *pkt_data;         
    int retval;
    cout << "----------- Start sniffing packet! ------------" << std::endl;
        while ((retval = pcap_next_ex(handler, &pkt_header, (const u_char **) &pkt_data)) >= 0)   {
        /// 
        bool is_end = false;
        if(*host == Host::Server) {
            is_end = server_packet_handler(pkt_header, pkt_data, handler);
        } else if (*host == Host::Client) {
            is_end = client_packet_handler(pkt_header, pkt_data, handler);
        }
        if (is_end) break;
    } 
    pcap_close(handler);
}

static void smain() {
    //char *sdev,*cdev;
    //std::vector<pthread_t*> threads;
    const char * sdev = server_interface.c_str();
    const char * cdev = client_interface.c_str();
    Host server = Host::Server;
    Host client = Host::Client;

    /*
    bool * server_is_server = new bool;
    *server_is_server = false;
    bool * client_is_server = new bool;
    *client_is_server = false;
    */
    while (!server_filename_queue.empty() && !client_filename_queue.empty()) {
        auto server_name = server_filename_queue.front();
        auto client_name = client_filename_queue.front();
        server_filename_queue.pop();
        client_filename_queue.pop();
        //if (server_name == "" || client_name == ""){
        //    exit(0);
        //}
        server_filename_queue.push(server_name);
        client_filename_queue.push(client_name);
        extract_trace(server_name, client_name);
        packet_handler_initiate();

        pthread_t* client_thread = new pthread_t;
        pthread_t* server_thread = new pthread_t;

        // create thread
        pthread_create(server_thread, NULL, &sniff_interface, (void *) &server);
        pthread_create(client_thread, NULL, &sniff_interface, (void *) &client);
        
        //pthread_create(client_thread, NULL, &sniff_interface, (void *) client_is_server);
        //pthread_create(server_thread, NULL, &sniff_interface, (void *) server_is_server);
        
        /// wait for threads to terminate.
        pthread_join(*server_thread, NULL);
        pthread_join(*client_thread, NULL);
        delete server_thread;
        delete client_thread;
    }
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
        ("auto", po::value<std::string>(),
            "Circularly use all the traces.\n")
        ("test", po::value<std::string>(),
            "Test functions.\n")
        ("trace", po::value<std::string>(),
            "Trace folder. "
            "Defaultly set to ./trace/")
        ("no", po::value<int>(),
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
        server_ip_vector.push_back("172.17.0.6");
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
        //server_filename_vector.emplace_back(std::move(server_name));
        //client_filename_vector.emplace_back(std::move(client_name));       
        
    } else if (vm.count("server") && vm.count("client")) {
        server_filename_queue.push(folder + vm["server"].as<std::string>());
        client_filename_queue.push(folder + vm["client"].as<std::string>());        
    } else if (vm.count("auto")) {
        int trace_count = std::stoi(vm["auto"].as<std::string>());
        for (int i = 1; i <= trace_count; ++i){
            std::string no = std::to_string(i);
            auto server_name = folder + no + "s.csv";
            auto client_name = folder + no + "c.csv";
            server_filename_queue.push(server_name);
            client_filename_queue.push(client_name);
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