/*
 * SqlHelper.h
 *
 *  Created on: Aug 20, 2015
 *      Author: olic
 */

#ifndef SQLHELPER_H_
#define SQLHELPER_H_

#include <stdio.h>
#include <string.h>
#include <sqlite3.h>

#include <memory>
#include <list>
#include <string>

using namespace std;
using std::shared_ptr;
using std::dynamic_pointer_cast;

#define SQL_MAX 4096
#define SQL_BLOB 0
#define SQL_TEXT 1
#define SQL_INT 2

class SqlValue {
public:
	string key;
	string strValue;
	int intValue;
	char *blobValue;
	int blobLen;
	SqlValue(string key, string value) {
		type = SQL_TEXT;

		this->key = key;
		this->strValue = value;
		intValue = -1;
		blobValue = NULL;
		blobLen = 0;
	}

	SqlValue(string key, int value) {
		type = SQL_INT;

		this->key = key;
		intValue = value;
		blobValue = NULL;
		blobLen = 0;
	}

	SqlValue(string key, char *value, int len) {
		type = SQL_BLOB;

		this->key = key;
		intValue = -1;
		blobValue = (char *)malloc(len);
		memcpy(blobValue, value, len);
		blobLen = len;
	}

	string getKey() {
		return this->key;
	}

	int getType() {
		return this->type;
	}

	virtual ~SqlValue() {
		if(blobValue)
			free(blobValue);
	}

private:
	int type;
};

typedef list<shared_ptr<SqlValue>> SqlRecord;

class SqlString : public SqlValue {
public:
	SqlString(string key, string value)
	: SqlValue(key, value) { }

	string getData() {
		return this->strValue;
	}
};

class SqlInteger : public SqlValue {
public:
	SqlInteger(string key, int value)
	: SqlValue(key, value) { }

	int getData() {
		return this->intValue;
	}
};

class SqlBlob : public SqlValue {
public:
	SqlBlob(string key, char *value, int len)
	: SqlValue(key, value, len) { }

	char *getData() {
		return this->blobValue;
	}

	int getLen() {
		return blobLen;
	}
};

class SqlHelper {
public:
	SqlHelper();
	virtual ~SqlHelper();

	bool createTbl(sqlite3 *db,
			string tbl, list<shared_ptr<SqlValue>> values);
	bool insertRec(sqlite3 *db,
			string tbl, list<shared_ptr<SqlValue>> values);
	SqlRecord selectRec(sqlite3 *db,
			string tbl, list<shared_ptr<SqlValue>> where);
	bool deleteRec(sqlite3 *db,
			string tbl, list<shared_ptr<SqlValue>> where);
};
#endif /* SQLHELPER_H_ */
