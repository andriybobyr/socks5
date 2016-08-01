#ifndef OPTION_H
#define OPTION_H

#include "main.h"

using namespace std;

class Options {
	public:
		bool read_options_file(string filename);
		string operator[](const char *key);
		vector<string> get_keys();
	private:
		map<string, string> params;
};



#endif