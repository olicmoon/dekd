/*
 * KeyStorage.h
 *
 *  Created on: Aug 20, 2015
 *      Author: olic
 */

#ifndef KEYSTORAGE_H_
#define KEYSTORAGE_H_

#include <sqlite3.h>

class KeyStorage {
public:
	KeyStorage(const char *path);
	virtual ~KeyStorage();

private:
	sqlite3 *mDb;
};

class Table {
public:
	Table(const char *tblName);
	virtual ~Table() { }

	virtual bool create() { return false; }
};

class KekTable : Table {
public:
	KekTable();
	virtual ~KekTable() { }

	virtual bool create();

};
#endif /* KEYSTORAGE_H_ */
