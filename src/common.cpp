/**
 * @file   common.cpp
 * @author Alex Ott <alexott@gmail.com>
 *
 * @brief
 *
 *
 */

#include "common.h"
#include "gsb-conf.h"

/**
 *
 *
 * @param argc
 * @param argv
 * @param cfg
 *
 * @return
 */
bool parseOptions(int argc, char** argv, po::variables_map& cfg) {
	bool result=false;
	try {
		std::string configFile;

		po::options_description command("Options");
		command.add_options()
			("config-file,c",
			 po::value<std::string>(&configFile)->default_value(std::string(__CONFFILE)),
			 "allows to specify a different configuration file location")
			("version,v", "Print version of the program and exit")
			("help,h", "Print help message and exit");

		po::variables_map vm;
		po::store(po::command_line_parser(argc, argv).options(command).run(), vm);
		po::notify(vm);

		if(vm.count("help")) {
			std::cerr << command << std::endl;
			return false;
		}

		if(vm.count("version")) {
			std::cerr << "Squid-GSB 0.1" << std::endl;
			std::cerr << "Config file: " << configFile << std::endl;
			return false;
		}

		po::options_description cfg_opt("Config file");
		cfg_opt.add_options()
			("black-hash-file",
			 po::value<std::string>()->default_value(std::string(__BHFILE)),
			 "")
			("black-url",
			 po::value<std::string>(),
			 "")
			("malware-hash-file",
			 po::value<std::string>()->default_value(std::string(__MHFILE)),
			 "")
			("malware-url",
			 po::value<std::string>(),
			 "")
			("key",
			 po::value<std::string>(),
			 "")
			("debug",
			 po::value<bool>()->default_value(false),
			 "")
			("emit-empty",
			 po::value<bool>()->default_value(false),
			 "")
			;

		// read config file
		std::ifstream is(configFile.c_str());
		if(!is) {
			std::cerr << command << std::endl;
			return false;
		}

		po::store(po::parse_config_file(is, cfg_opt), cfg);
		po::notify(cfg);
		is.close();

		result=true;
	} catch (std::exception& x) {
#ifdef DEBUG
		std::cerr << "Catch exception: " << x.what() << std::endl;
#endif
	}

	return result;
}


