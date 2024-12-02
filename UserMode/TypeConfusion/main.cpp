#include <iostream>
#include <cstring>

using namespace std;


#define MAX_DATA_LEN		0x100

static void vuln(void);

class offline {
public:
	virtual void offline_end() = 0;
};

class offline_a: public offline {
public:
	offline_a() {
		strncpy(desc, "hello c++\0", MAX_DATA_LEN);
	}

	virtual void offline_end() {
		cout << desc << endl;
	}

	char desc[MAX_DATA_LEN];
};

class offline_b: public offline {
public:
	virtual void offline_end() {
		desc();
	}

	void (*desc)(void);
};

static void vuln(void) {
	system("/bin/sh");
}

int main(void)
{
	string buf;
	offline* tmpB;
	offline_a* apt;

	tmpB = new offline_b();
	apt = static_cast<offline_a*>(tmpB);

	cout << "please input something" << endl;
	cin >> buf;
	strncpy(apt->desc, buf.c_str(), MAX_DATA_LEN);

	apt->offline_end();
}
