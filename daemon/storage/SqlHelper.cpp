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

	for (list<shared_ptr<SqlValue>>::iterator it = values.begin();
			it != values.end(); it++) {
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

//	printf("sql : %s\n", sql.c_str());

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
	string sql;

	int size = values.size();

	if(size == 0) {
		printf("%s failed, empty column list\n", __func__);
		return false;
	}

	sql = "INSERT INTO " + tbl + "(";

	for (list<shared_ptr<SqlValue>>::iterator it = values.begin();
			it != values.end(); it++) {
		if(distance(values.begin(), it) != 0) sql += ",";
		sql += (*it)->getKey();
	}

	sql += ") VAlUES (";

	for (list<shared_ptr<SqlValue>>::iterator it = values.begin();
			it != values.end(); it++) {
		if(distance(values.begin(), it) != 0) sql += ",";
		sql += "?";
	}

	sql += ")";
//	printf("sql : %s\n", sql.c_str());

	do {
		// INSERT INTO KEK(ALIAS,KEK_NAME,KEY,KEK_AUTH_TAG) VALUES (?, ?, ?, ?)
		rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, NULL);
		if( rc!=SQLITE_OK ){
			printf("Failed to prepare(%s) sql : %s\n",
					sqlite3_errmsg(db), sql.c_str());
			return false;
		}

		for (list<shared_ptr<SqlValue>>::iterator it = values.begin();
				it != values.end(); it++) {
			int type = (*it)->getType();
			int idx = distance(values.begin(), it);

			if(type == SQL_BLOB) {
				shared_ptr<SqlBlob> v =
						dynamic_pointer_cast<SqlBlob> (*it);
				rc = sqlite3_bind_blob(stmt, idx+1,
						(const void *)v->getData(), v->getLen(), SQLITE_STATIC);
				if(rc != SQLITE_OK)
					printf("Failed to insert into %s col:%d, rc:%d (%s)\n",
							tbl.c_str(), idx, rc, sqlite3_errmsg(db));
			} else if(type == SQL_INT) {
				shared_ptr<SqlInteger> v =
						dynamic_pointer_cast<SqlInteger> (*it);
				rc = sqlite3_bind_int(stmt, idx+1, v->getData());
				if(rc != SQLITE_OK)
					printf("Failed to insert into %s col:%d, rc:%d (%s)\n",
							tbl.c_str(), idx, rc, sqlite3_errmsg(db));
			} else if(type == SQL_TEXT) {
				shared_ptr<SqlString> v =
						dynamic_pointer_cast<SqlString> (*it);
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
			return false;
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
		return false;

	return true;
}

list<shared_ptr<SqlValue>> SqlHelper::selectRec(sqlite3 *db,
		string tbl, list<shared_ptr<SqlValue>> where) {
	string sql;
	list<shared_ptr<SqlValue>> null;

	sql = "SELECT * from " + tbl + " where ";
	for (list<shared_ptr<SqlValue>>::iterator it = where.begin();
			it != where.end(); it++) {
		if((*it)->getType() == SQL_TEXT) {
			shared_ptr<SqlString> value = dynamic_pointer_cast<SqlString>(*it);
			if(distance(where.begin(), it) != 0) sql += " and ";

			sql += value->getKey() + "=\"" + value->getData() + "\"";
		}
	}

	sqlite3_stmt *stmt;
	int rc = sqlite3_prepare_v2(db, sql.c_str(), sql.length() + 1, &stmt, NULL);
	if( rc!=SQLITE_OK ){
		printf("Failed to prepare(%s) sql : %s\n",
				sqlite3_errmsg(db), sql.c_str());
		return null;
	}

	list<shared_ptr<SqlValue>> result;
	while (1) {
		int s;

		s = sqlite3_step (stmt);
		if (s == SQLITE_ROW) {
			const char *tmp;
			int colCnt = sqlite3_column_count(stmt);

			for(int i=0; i<colCnt ; i++) {
		          switch (sqlite3_column_type(stmt, i)) {
		            case SQLITE_INTEGER:
//		            	printf("integer value[%d] : name[%s] val[%d]\n", i,
//		            			sqlite3_column_origin_name(stmt, i),
//		            			sqlite3_column_int(stmt, i));
		            	result.push_back(shared_ptr<SqlInteger>(
		            			new SqlInteger(
		            					sqlite3_column_origin_name(stmt, i),
				            			sqlite3_column_int(stmt, i)
		            					)));
		            	break;
		            case SQLITE_TEXT:
//		            	printf("text value[%d] : name[%s] val[%s]\n", i,
//		            			sqlite3_column_origin_name(stmt, i),
//		            			sqlite3_column_text(stmt, i));
		            	result.push_back(shared_ptr<SqlString>(
		            			new SqlString(
		            					sqlite3_column_origin_name(stmt, i),
		            					(const char *)sqlite3_column_text(stmt, i)
		            					)));
		            	break;
		            case SQLITE_BLOB:
		            	/*Write to a file, dynamic memory ...*/
		            	break;
		          }
			}
		} else if (s == SQLITE_DONE)
			break;
		else {
			printf("Failed.\n");
			sqlite3_finalize(stmt);
			return null;
		}
	}

	sqlite3_finalize(stmt);
	return result;
}

bool SqlHelper::deleteRec(sqlite3 *db,
		string tbl, list<shared_ptr<SqlValue>> where) {
	return false;
}
