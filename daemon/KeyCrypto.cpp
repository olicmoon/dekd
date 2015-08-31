/*
 * KeyCrypto.cpp
 *
 *  Created on: Aug 17, 2015
 *      Author: olic
 */

#include "KeyCrypto.h"
#include "storage/KeyStorage.h"

KeyCryptoManager *KeyCryptoManager::_instance = new KeyCryptoManager();

KeyCrypto::KeyCrypto(string alias) {
	printf("Creating KeyCrypto %s\n", alias.c_str());

	this->_alias = alias;

	_state = State::Uninitialized;
	_oldState = State::Uninitialized;
	StateDiagram[Action::getCode(Uninitialized, Boot)] = Locked;
	StateDiagram[Action::getCode(Uninitialized, Create)] = Locked;

	StateDiagram[Action::getCode(Locked, Unlock)] = Unlocked;
	StateDiagram[Action::getCode(Locked, Remove)] = Uninitialized;

	StateDiagram[Action::getCode(Unlocked, Lock)] = Locked;
	StateDiagram[Action::getCode(Unlocked, Remove)] = Uninitialized;

	_pubKey = NULL;
	_privKey = NULL;
	_symKey = NULL;
}

KeyCrypto::~KeyCrypto() {
	printf("Destroying KeyCrypto %s\n", _alias.c_str());
	if(_pubKey != NULL) delete _pubKey;
	if(_privKey != NULL) delete _privKey;
	if(_symKey != NULL) delete _symKey;
}

bool KeyCrypto::transit(Event event) {
	int action = Action::getCode(_state, event);
	printf("%s : current state[0x%0.8x], event[0x%0.8x] (action[0x%0.8x])\n",
			__func__, _state, event, action);

	if (StateDiagram.find(action) == StateDiagram.end()) {
		printf("%s : Failed to transit from state[0x%0.8x] by event[0x%0.8x]\n",
				__func__, _state, event);
		return false;
	}

	_oldState = _state;
	_state = StateDiagram[action];
	printf("%s : transited oldState[0x%0.8x]->state[0x%0.8x], event[0x%0.8x]\n",
			__func__, _oldState, _state, event);

	return true;
}


EncItem *KeyCrypto::encrypt(Item *item) {
	if(_symKey)
		return aes_gcm_encrypt(item, _symKey);
	else if(_pubKey)
		return ecdh_encrypt(item, (PubKey *)_pubKey);

	printf("KeyCrypto(%s)::encrypt, no key available\n", _alias.c_str());
	return NULL;
}

Item *KeyCrypto::decrypt(EncItem *eitem) {
	switch(eitem->encBy) {
	case CryptAlg::AES:
		if(_symKey)
			return aes_gcm_decrypt(eitem, _symKey);
		printf("KeyCrypto(%s)::decrypt, sym-key not available\n", _alias.c_str());
		break;
	case CryptAlg::ECDH:
		if(_privKey)
			return ecdh_decrypt(eitem, _privKey);
		printf("KeyCrypto(%s)::decrypt, priv-key not available\n", _alias.c_str());
		break;
	default:
		printf("unknown alg<%d>\n", eitem->encBy);
		return NULL;
	}

	return NULL;
}

KeyCryptoManager::KeyCryptoManager() {
	KekStorage *kekStorage = KekStorage::getInstance();

	list<shared_ptr<SqlRecord>> foundRecords = kekStorage->getAllKek();
	for (list<shared_ptr<SqlRecord>>::iterator it = foundRecords.begin();
			it != foundRecords.end(); it++) {
		string alias;
		list<shared_ptr<SqlValue>> values = (*it)->getValues();
		for (list<shared_ptr<SqlValue>>::iterator it = values.begin();
				it != values.end(); it++) {
			if((*it)->getKey().compare(KEK_COL_ALIAS) == 0)
				alias = (dynamic_pointer_cast<SqlString> (*it))->getData();
		}

		if(this->exists(alias))
			continue;
		else
			createKeyCrypto(alias);

		printf("%s found [%s]\n", __func__, alias.c_str());

		KeyCrypto *kc = getKeyCrypto(alias);
		if(kc == NULL) {
			printf("FATAL can't get KeyCrypto[%s] instance\n",
					alias.c_str());
			exit(1);
		}

		PubKey *pubKey =
				kekStorage->retrievePubKey(alias, CryptAlg::ECDH);
		if(pubKey == NULL) {
			printf("pubkey not found from KeyCrypto[%s]\n",
					alias.c_str());

			clrKeyCrypto(alias);
			continue;
		}

		if(!kc->transit(KeyCrypto::Event::Boot)) {
			printf("FATAL can't transit KeyCrypto[%s] to Boot state\n",
					alias.c_str());
			exit(1);
		}

		kc->setPubKey(pubKey);
	}
}

