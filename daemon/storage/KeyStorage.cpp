/*
 * KeyStorage.cpp
 *
 *  Created on: Aug 20, 2015
 *      Author: olic
 */

#include "KeyStorage.h"

#include <stdio.h>
#include <stdlib.h>
#include <List.h>

KeyStorage::KeyStorage(const char *path) {
	int rc = sqlite3_open(path, &this->mDb);
	if( rc ){
		printf("Can't open database: %s\n", sqlite3_errmsg(this->mDb));
		sqlite3_close(this->mDb);
		exit(1);
	}
}

KeyStorage::~KeyStorage() {
	// TODO Auto-generated destructor stub
}

