/**
 * @file   gsb-updater.cpp
 * @author Alex Ott <alexott@gmail.com>
 * 
 * @brief  
 * 
 * 
 */

#include "common.h"
#include <boost/lexical_cast.hpp>
//#include <boost/asio.hpp>
#include <boost/regex.hpp>
#include <iostream>


void readIfExists(const fs::path& fname,HashData& h) {
	if(fs::exists(fname)) {
		std::ifstream ifs(fname.file_string().c_str(), std::ios::binary);
		if(ifs) {
			boost::archive::text_iarchive ia(ifs);
			ia >> h;
		} else {
#ifdef DEBUG
			std::cerr << "Error opening " << fname << std::endl;
#endif
			return;
		}
	}
}

void writeHash(const fs::path& fname,HashData& h) {
	fs::path tname=fname+".tmp";
	std::ofstream ofs(fname.file_string().c_str(), std::ios::binary);
	if (!ofs) {
#ifdef DEBUG
		std::cerr << "Error opening " << tname << std::endl;
#endif
		return ;
	}
	boost::archive::text_oarchive oa(ofs);
	oa << h;
	ofs.close();
	if(fs::exists(fname)){
		if (!fs::remove(fname)) {
#ifdef DEBUG
			std::cerr << "Error removing " << fname << std::endl;
#endif
			return ;
		}
	}
	fs::rename(tname,fname);
}

bool readData(HashData& h, std::istream& is) {
	std::string ts;
	boost::smatch m;
	
	std::getline(is,ts);
	boost::regex hr("\\[(\\S+) (\\d)\\.(\\d+)( update)?\\]");

	if(boost::regex_search(ts, m, hr, boost::match_extra)){
		std::cout << m[1].str() << " " << m[2].str() << " " << m[3].str() << std::endl;

		if(m[4].str() != " update") {
#ifdef DEBUG
			std::cerr << "Full update of hash" << std::endl;
#endif
			h.hashes.clear();
		}
		
			
	} else {
#ifdef DEBUG
		std::cerr << "First line not matched" << std::endl;
#endif
	    return false;
	}
	
	
	
}


bool updateHash(HashData& h) {
	std::ifstream ifs("test-data/black-hash.txt",std::ios::binary);
	if(!ifs)
		return false;
	bool result=false;
	try {
		result=readData(h,ifs);
	} catch(std::exception& x) {
#ifdef DEBUG
		std::cerr << "Catch exception: " << x.what() << std::endl;
#endif
	}

	return result;
}


int main(int argc, char** argv) {
	fs::path bhFileName("black-hash.dat"),mhFileName("malware-hash.dat");
	
	HashData bh;
	bh.name="goog-black-hash";
	readIfExists(bhFileName,bh);
	
// 	HashData mh;
// 	mh.name="goog-malware-hash";
// 	readIfExists(mhFileName,mh);

	
	if(updateHash(bh)) {
#ifdef DEBUG
		std::cerr << "Hash updated" std::endl;
#endif
		writeHash(bhFileName,bh);
	}
	
}
