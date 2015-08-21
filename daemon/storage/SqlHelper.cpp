/*
 * SqlHelper.cpp
 *
 *  Created on: Aug 20, 2015
 *      Author: olic
 */

#include "SqlHelper.h"

SqlHelper::SqlHelper() {
	// TODO Auto-generated constructor stub

}

SqlHelper::~SqlHelper() {
	// TODO Auto-generated destructor stub
}

bool SqlHelper::createTbl(sqlite3 *db,
		string tbl, list<shared_ptr<SqlValue>> values) {
	string sql;
	char *zErrMsg = 0;

	int size = values.size();

	if(size == 0) {
		printf("%s failed, empty column list\n", __func__);
		return false;
	}

	sql = "CREATE TABLE " + tbl + "(";

	for (list<shared_ptr<SqlValue>>::iterator it = values.begin(); it != values.end(); it++) {
		shared_ptr<SqlValue>value = *it;
		int type = value->getType();
		if(distance(values.begin(), it) != 0) sql += ", ";

		if(type == SQL_TEXT) {
			shared_ptr<SqlString> v = dynamic_pointer_cast<SqlString> (value);
			sql += v->getKey() + " " + v->getData();
		} else
			return false;
	}

	sql += ")";

	printf("sql : %s\n", sql.c_str());

	int rc = sqlite3_exec(db, sql.c_str(), NULL, 0, &zErrMsg);
	if( rc!=SQLITE_OK ){
		printf("SQL error: %s\n", zErrMsg);
		sqlite3_free(zErrMsg);
		return false;
	}

	return true;
}

bool SqlHelper::insertRec(sqlite3 *db,
		string tbl, list<shared_ptr<SqlValue>> values) {
	return false;
}

string SqlHelper::buildSelectQuery(sqlite3 *db,
		string tbl, list<shared_ptr<SqlValue>> where) {
	return NULL;
}

bool SqlHelper::deleteRec(sqlite3 *db,
		string tbl, list<shared_ptr<SqlValue>> where) {
	return false;
}
