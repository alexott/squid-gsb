/**
 * @file   gsb-updater.cpp
 * @author Alex Ott <alexott@gmail.com>
 * 
 * @brief  
 * 
 * 
 */

#include "common.h"
#include <boost/asio.hpp>
#include <boost/regex.hpp>
#include <iostream>

namespace ba=boost::asio;

bool runDebug;
std::string key;

/** 
 * read hash from a given file
 * 
 * @param fname file name
 * @param h hash to read
 */
void readIfExists(const fs::path& fname,HashData& h) {
	if(fs::exists(fname)) {
		std::ifstream ifs(fname.file_string().c_str(), std::ios::binary);
		if(ifs) {
			boost::archive::text_iarchive ia(ifs);
			ia >> h;
		} else {
			if(runDebug)
				std::cerr << "Error opening " << fname << std::endl;

			return;
		}
	}
}

/** 
 * Write given hash to file
 * 
 * @param fname filename
 * @param h hash file
 */
void writeHash(const fs::path& fname,HashData& h) {
	try {
		fs::path tname=fname.file_string() + ".tmp";
		std::ofstream ofs(tname.file_string().c_str(), std::ios::binary);
		if (!ofs) {
			if(runDebug)
				std::cerr << "Error opening " << tname << std::endl;

			return ;
		}
		boost::archive::text_oarchive oa(ofs);
		oa << h;
		ofs.close();
		if(fs::exists(fname)){
			if (!fs::remove(fname)) {
				if(runDebug)
					std::cerr << "Error removing " << fname << std::endl;

				return ;
			}
		}
		fs::rename(tname,fname);
	} catch(std::exception& x) {
		if(runDebug)
			std::cerr << "Catch exception: " << x.what() << std::endl;

	}
	
}

bool readData(HashData& h, std::istream& is) {
	std::string ts;
	boost::smatch m;
	
	std::getline(is,ts);
	boost::regex hr("\\[(\\S+) (\\d)\\.(\\d+)( update)?\\]");

	if(boost::regex_search(ts, m, hr, boost::match_extra)){
		if(runDebug)
			std::cerr << m[1].str() << " " << m[2].str() << " " << m[3].str() << std::endl;
		
		if(m[1].str() != h.name) {
			if(runDebug)
				std::cerr << "Wrong name of hash \"" << m[1].str() <<
					"\" instead of " <<h.name << std::endl;

			return false;
		}
		if(m[4].str() != " update") {
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
					break;
				}
				if(boost::regex_search(ts, m, sr, boost::match_extra)){
					if(m[1].str() == "+") {
						h.hashes.insert(m[2].str());
					} else if (m[1].str() == "-") {
					    if((hi=h.hashes.find(m[2].str())) != h.hashes.end()) {
							h.hashes.erase(hi);
						}
					} else {
					}
				} else {
					if(runDebug)
						std::cerr << "String not matched" << std::endl;

				}
			} catch (std::exception& x) {
				if(runDebug)
					std::cerr << "Catch exception: " << x.what() << std::endl;

			}
		}
		
			
	} else {
		if(runDebug)
			std::cerr << "First line not matched" << std::endl;

	    return false;
	}
	
	return true;
}

/** 
 * Update given hash file
 * 
 * @param h referense to hash file
 * 
 * @return true on successfull update
 */
bool updateHash(HashData& h) {
	bool result=false;
	try {
		std::string host("sb.google.com");
		
		ba::ip::tcp::iostream s(host.c_str(), "http");
		if(!s) {
			if(runDebug)
				std::cerr << "Error opening stream to " << host << std::endl;

			return false;
		}
		
		s << "GET " << "/safebrowsing/update?client=api&apikey="
		  << key << "&version=" << h.name << ":" << h.majorVersion
		  << ":" << h.minorVersion << " HTTP/1.1\r\n";
		s << "Host: " << host << "\r\n\r\n" << std::flush;
		
		
		boost::regex sr("HTTP/\\d\\.\\d (\\d+) \\S+");
		std::string ts;
		boost::smatch m;
		const std::string cls("Content-Length: ");
		const int clsl=16;

		std::getline(s,ts);
		if(runDebug)
			std::cerr << ts << std::endl;

		if(!boost::regex_search(ts, m, sr, boost::match_extra)){
			if(runDebug)
				std::cerr << "Bad response string: " << ts << std::endl;

			return false;
		}
		if(m[1].str() != "200") {
			if(runDebug)
				std::cerr << "Non-successfull answer: " << m[1].str() << std::endl;

			return false;
		}

		int cl=-1;
		while(true) {
			std::getline(s,ts);
			boost::trim(ts);
			if(runDebug)
				std::cerr << ts << std::endl;
 
			if (s.eof() || s.fail()) {
				if(runDebug)
					std::cerr << "End of stream" << std::endl;

				return false;
			}
			if (ts == "" || ts == "\r") {
				break;
			}
			if(boost::istarts_with(ts,cls)) {
				cl=boost::lexical_cast<int>(ts.substr(clsl));
			}
		}
		if(cl != 0)
			result=readData(h,s);
	} catch(std::exception& x) {
		if(runDebug)
			std::cerr << "Catch exception: " << x.what() << std::endl;

	}

	return result;
}


int main(int argc, char** argv) {
	po::variables_map cfg;
	if(!parseOptions(argc,argv,cfg))
		return 0;

	fs::path bhFileName,mhFileName;
	try {
		runDebug=cfg["debug"].as<bool>();
		bhFileName=cfg["black-hash-file"].as<std::string>();
		mhFileName=cfg["malware-hash-file"].as<std::string>();
		key=cfg["key"].as<std::string>();
	} catch (...) {
		std::cerr << "Please check configuration file!" << std::endl;
		return 1;
	}

	
	HashData bh;
	bh.name="goog-black-hash";
	readIfExists(bhFileName,bh);
	
 	HashData mh;
 	mh.name="goog-malware-hash";
 	readIfExists(mhFileName,mh);

	int mnv, mjv;
	mjv=bh.majorVersion;
	mnv=bh.minorVersion;
	if(updateHash(bh)) {
		std::cerr << "Black hash updated from " << mjv << "." << mnv
				  << " to " << bh.majorVersion << "." << bh.minorVersion
				  << std::endl;

		writeHash(bhFileName,bh);
	}
	mjv=mh.majorVersion;
	mnv=mh.minorVersion;
	if(updateHash(mh)) {
		std::cerr << "Malware hash updated from " << mjv << "." << mnv
				  << " to " << mh.majorVersion << "." << mh.minorVersion
				  << std::endl;

		writeHash(mhFileName,mh);
	}
	
}
