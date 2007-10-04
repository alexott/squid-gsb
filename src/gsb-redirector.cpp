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
	fs::path fname;
	std::string url;
	std::time_t wtime;

	/** 
	 * Update file with hash, using last update time of file
	 * 
	 */
	void updateHash() {
		std::time_t nt;
		if(fs::exists(fname)) {
			if(wtime < (nt=last_write_time(fname))) {
#ifdef DEBUG
				std::cerr << "Going to read " << fname.file_string() << std::endl;
#endif
				std::ifstream ifs(fname.file_string().c_str(), std::ios::binary);
				if(!ifs) {
#ifdef DEBUG
					std::cerr << "Error opening " << fname << std::endl;
#endif
					return;
				}
				boost::archive::text_iarchive ia(ifs);
				ia >> h;
				wtime=nt;
			}
#ifdef DEBUG
		} else {
			std::cerr << fname <<  " doesn't exists" << std::endl;
#endif
		}
	}
	
	HashFile(): fname(""), url(""), wtime(0) { }

	/** 
	 * Check is url in hash?
	 * 
	 * @param sv list of generated url's
	 * @param u new url, that will updated if match found
	 * 
	 * @return if one of url's found in hash
	 */
	bool checkHash(StringVector& sv, std::string& u) {
		if(h.minorVersion == -1)
			return false;
		
		StringVector::iterator it=sv.begin();
		StringVector::iterator itEnd=sv.end();
		HashData::HashSet::iterator hi;
		for(; it != itEnd; ++it) {
			if ((hi=h.hashes.find(*it)) != h.hashes.end()) {
#ifdef DEBUG
			    std::cerr << "Found match in " << h.name
						  << ": " << *it << std::endl;
#endif
				u=url;
				return true;
			}
		}
		return false;
	}
	
} ;

/** 
 * Generate list of MD5 hashes
 * 
 * @param url 
 * @param sv 
 * 
 * @return true, if success, false - if no variants generated
 */
bool generateVariants(const std::string& url, StringVector& sv) {
	sv.clear();
	

	return sv.size() > 0;
}



int main(int argc, char** argv) {
	//read settings

	//
	HashFile bh;
	bh.fname="black-hash.dat";
	bh.url="black hash url";
	
	HashFile mh;
	mh.fname="malware-hash.dat";
	bh.url="malware hash url";

	std::string url;
	StringVector sv;
	while(true) {
		std::getline(std::cin,url);
		mh.updateHash();
		bh.updateHash();
		if(bh.h.minorVersion == -1 && mh.h.minorVersion == -1) { 
			std::cout << "" << std::endl;
			continue;
		}
		if(!generateVariants(url,sv)) {
			std::cout << "" << std::endl;
			continue;
		}
		if(bh.checkHash(sv,url) || mh.checkHash(sv,url))
			std::cout << url << std::endl;
		else
			std::cout << "" << std::endl;
	}

	return 0;
}
