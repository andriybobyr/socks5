#include "options.h"

bool Options::read_options_file(string filename) {
	FILE *hFile = NULL;
	char buffers[STRING_SIZE];
	char *equals;

	memset(buffers, 0, STRING_SIZE);

	if(!(hFile = fopen(filename.c_str(), "r")))
		return false;

	while(fgets(buffers, STRING_SIZE, hFile)) {
		/* Remove the \n*/
		char *t = strchr(buffers, '\n');
		if(t) *t = '\0';

		/* Ignore lines with no equal signs or comment lines. */
		if(buffers[0] == '#') continue;
		if(!(equals = strchr(buffers, '='))) continue;

		*equals = '\0';

		params[buffers] = equals + 1;
	}

	fclose(hFile);

	return true;
}

string Options::operator[](const char *key) {
	return params[key];
}

vector<string> Options::get_keys()
{
	vector<string> keys;

	for(map<string, string>::iterator i=params.begin(); i!=params.end(); i++) {
		keys.push_back((*i).first);
	}

	return keys;

}


















