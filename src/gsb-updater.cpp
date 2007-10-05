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
#include <boost/asio.hpp>
#include <boost/regex.hpp>
#include <iostream>

namespace ba=boost::asio;

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
	try {
		fs::path tname=fname.file_string() + ".tmp";
		std::ofstream ofs(tname.file_string().c_str(), std::ios::binary);
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
	} catch(std::exception& x) {
#ifdef DEBUG
		std::cerr << "Catch exception: " << x.what() << std::endl;
#endif
	}
	
}

bool readData(HashData& h, std::istream& is) {
	std::string ts;
	boost::smatch m;
	
	std::getline(is,ts);
	boost::regex hr("\\[(\\S+) (\\d)\\.(\\d+)( update)?\\]");

	if(boost::regex_search(ts, m, hr, boost::match_extra)){
		std::cerr << m[1].str() << " " << m[2].str() << " " << m[3].str() << std::endl;
		if(m[1].str() != h.name) {
#ifdef DEBUG
			std::cerr << "Wrong name of hash \"" << m[1].str() <<
				"\" instead of " <<h.name << std::endl;
#endif
			return false;
		}
		if(m[4].str() != " update") {
#ifdef DEBUG
			std::cerr << "Full update of hash" << std::endl;
#endif
			h.hashes.clear();
		}
		h.majorVersion=boost::lexical_cast<int>(m[2].str());
		h.minorVersion=boost::lexical_cast<int>(m[3].str());
		
		boost::regex sr("([+-])(\\S+)");
		HashData::HashSet::iterator hi;
		while(true) {
			try {
				std::getline(is,ts);
				if (is.eof() || is.fail() || ts == "") {
#ifdef DEBUG
					std::cerr << "End of stream" << std::endl;
#endif
					break;
				}
				if(boost::regex_search(ts, m, sr, boost::match_extra)){
					if(m[1].str() == "+") {
#ifdef DEBUG
						std::cerr << "Add hash " << m[2].str() << std::endl;
#endif
						h.hashes.insert(m[2].str());
					} else if (m[1].str() == "-") {
#ifdef DEBUG
						std::cerr << "Remove hash " << m[2].str() << std::endl;
#endif
					    if((hi=h.hashes.find(m[2].str())) != h.hashes.end()) {
							h.hashes.erase(hi);
						}
					} else {
#ifdef DEBUG
						std::cerr << "Unknown first symbol " << m[1].str() << " "
								  << m[2].str() << std::endl;
#endif
					}
				} else {
#ifdef DEBUG
					std::cerr << "String not matched" << std::endl;
#endif
				}
			} catch (std::exception& x) {
#ifdef DEBUG
				std::cerr << "Catch exception: " << x.what() << std::endl;
#endif
			}
		}
		
			
	} else {
#ifdef DEBUG
		std::cerr << "First line not matched" << std::endl;
#endif
	    return false;
	}
	
	return true;
}


bool updateHash(HashData& h) {
	bool result=false;
	try {
		std::string host("sb.google.com");
		std::string key("ABQIAAAAABwg5aWV0j9eN6t-GBI64hTicPALuOOU0tufrSiosNnEET78Og");
		
		ba::ip::tcp::iostream s(host.c_str(), "http");
		if(!s) {
#ifdef DEBUG
			std::cerr << "Error opening stream to " << host << std::endl;
#endif
			return false;
		}
		
		s << "GET " << "/safebrowsing/update?client=api&apikey="
		  << key << "&version=" << h.name << ":" << h.majorVersion
		  << ":" << h.minorVersion << " HTTP/1.1\r\n";
		s << "Host: " << host << "\r\n\r\n" << std::flush;
		
		
		boost::regex sr("HTTP/\\d\\.\\d (\\d+) \\S+");
		std::string ts;
		boost::smatch m;

		std::getline(s,ts);
#ifdef DEBUG
		std::cerr << ts << std::endl;
#endif
		
		if(!boost::regex_search(ts, m, sr, boost::match_extra)){
#ifdef DEBUG
			std::cerr << "Bad response string: " << ts << std::endl;
#endif
			return false;
		}
		if(m[1].str() != "200") {
#ifdef DEBUG
			std::cerr << "Non-successfull answer: " << m[1].str() << std::endl;
#endif
			return false;
		}
		
		while(true) {
			std::getline(s,ts);
			std::cerr << ts << std::endl;
			if (s.eof() || s.fail()) {
#ifdef DEBUG
				std::cerr << "End of stream" << std::endl;
#endif
				return false;
			}
			if (ts == "" || ts == "\r") {
				break;
			}
		}
			
		result=readData(h,s);
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
	
 	HashData mh;
 	mh.name="goog-malware-hash";
 	readIfExists(mhFileName,mh);

	
	if(updateHash(bh)) {
#ifdef DEBUG
		std::cerr << "Black hash updated" << std::endl;
#endif
		writeHash(bhFileName,bh);
	}
	if(updateHash(mh)) {
#ifdef DEBUG
		std::cerr << "Malware hash updated" << std::endl;
#endif
		writeHash(mhFileName,mh);
	}
	
}
