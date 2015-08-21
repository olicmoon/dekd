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
	sqlite3_stmt *stmt;
	int rc;
	char *zErrMsg = 0;
	string sql;

	int size = values.size();

	if(size == 0) {
		printf("%s failed, empty column list\n", __func__);
		return false;
	}

	sql = "INSERT INTO " + tbl + "(";

	for (list<shared_ptr<SqlValue>>::iterator it = values.begin();
			it != values.end(); it++) {
		shared_ptr<SqlValue>value = *it;
		if(distance(values.begin(), it) != 0) sql += ",";

		shared_ptr<SqlString> v = dynamic_pointer_cast<SqlString> (value);
		sql += v->getKey();
	}

	sql += ") VAlUES (";

	for (list<shared_ptr<SqlValue>>::iterator it = values.begin();
			it != values.end(); it++) {
		if(distance(values.begin(), it) != 0) sql += ",";
		sql += "?";
	}

	sql += ")";
	printf("sql : %s\n", sql.c_str());

	do {
		// INSERT INTO KEK(ALIAS,KEK_NAME,KEY,KEK_AUTH_TAG) VALUES (?, ?, ?, ?)
		rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);
		if( rc!=SQLITE_OK ){
			printf("Failed to prepare(%s) sql : %s\n",
					sqlite3_errmsg(db), sql.c_str());
			return -1;
		}

		for (list<shared_ptr<SqlValue>>::iterator it = values.begin();
				it != values.end(); it++) {
			shared_ptr<SqlValue>value = *it;
			int idx = distance(values.begin(), it);
			int type = value->getType();

			if(type == SQL_BLOB) {
				shared_ptr<SqlBlob> v =
						dynamic_pointer_cast<SqlBlob> (value);
				int len;
				rc = sqlite3_bind_blob(stmt, idx+1,
						(const void *)v->getData(), v->getLen(), SQLITE_STATIC);
				if(rc != SQLITE_OK)
					printf("Failed to insert into %s col:%d, rc:%d (%s)\n",
							tbl.c_str(), idx, rc, sqlite3_errmsg(db));
			} else if(type == SQL_INT) {
				shared_ptr<SqlInteger> v =
						dynamic_pointer_cast<SqlInteger> (value);
				rc = sqlite3_bind_int(stmt, idx+1, v->getData());
				if(rc != SQLITE_OK)
					printf("Failed to insert into %s col:%d, rc:%d (%s)\n",
							tbl.c_str(), idx, rc, sqlite3_errmsg(db));
			} else if(type == SQL_TEXT) {
				shared_ptr<SqlString> v =
						dynamic_pointer_cast<SqlString> (value);
				rc = sqlite3_bind_text(stmt, idx+1,
						v->getData().c_str(), -1, SQLITE_STATIC);
				if(rc != SQLITE_OK)
					printf("Failed to insert into %s col:%d, rc:%d (%s)\n",
							tbl.c_str(), idx, rc, sqlite3_errmsg(db));
			}
		}

		rc = sqlite3_step(stmt);
		if( rc!=SQLITE_ROW && rc!=SQLITE_DONE ) {
			printf("Failed  to insert : %s[rc:%d]\n", sqlite3_errmsg(db), rc);
			return -1;
		}

		/* Finalize the virtual machine. This releases all memory and other
		** resources allocated by the sqlite3_prepare() call above.
		*/
		rc = sqlite3_finalize(stmt);

		/* If sqlite3_finalize() returned SQLITE_SCHEMA, then try to execute
		 ** the statement again.
		 */
	} while( rc==SQLITE_SCHEMA );

	if(rc)
		return -rc;

	return 0;
}

string SqlHelper::buildSelectQuery(sqlite3 *db,
		string tbl, list<shared_ptr<SqlValue>> where) {
	return NULL;
}

bool SqlHelper::deleteRec(sqlite3 *db,
		string tbl, list<shared_ptr<SqlValue>> where) {
	return false;
}
