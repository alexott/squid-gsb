/**
 * @file   gsb-redirector.cpp
 * @author Alex Ott <alexott@gmail.com>
 * 
 * @brief  
 * 
 * 
 */

#include "common.h"
#include <iostream>

struct HashFile {
	HashData h;
	std::string fname;

	void updateHash() {
		if(fs::exists(fname)) {
			std::ifstream ifs(fname.c_str(), std::ios::binary);
			if(!ifs) {
				std::cerr << "Error opening " << fname << std::endl;
			}
			boost::archive::text_iarchive ia(ifs);
			ia >> h;
		} else {
			std::cerr << fname <<  " doesn't exists" << std::endl;
		}
	}
	
	
} ;


bool generateVariants(const std::string& url, StringVector& sv) {


	return true;
}



int main(int argc, char** argv) {
	//read settings
	
	HashFile bh;
	bh.fname="black-hash.dat";
	bh.updateHash();
	
	HashFile mh;
	mh.fname="malware-hash.dat";
	mh.updateHash();

	// should we do this? or start work, and regularly check for updates?
	if(bh.h.majorVersion == 0 && mh.h.majorVersion == 0) { 
		std::cerr << "Both hashed doesn't exists. Exiting...." << std::endl;
		return 1;
	}
	
	std::string url;
	StringVector sv;
	while(true) {
		std::getline(std::cin,url);
		if(!generateVariants(url,sv)) {
			std::cout << "" << std::endl;
			continue;
		}
		
	}

	return 0;
}
